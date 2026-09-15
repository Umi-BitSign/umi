# ruff: noqa: F811
import pytest
from pydantic import ValidationError

import umi.registration_bridge as bridge
from tests.test_registration_bridge import BLOCK, decision, hotkey, replace_participant
from tests.test_registration_bridge_funding import setup  # noqa: F401
from tests.test_registration_bridge_ongoing import ongoing
from umi.protocol import canonical_json_bytes


def frozen(setup):
    _, report, signer, _, _ = setup
    body = bridge.RegistrationBridgeFrozenPolicyBody.model_validate(
        {
            **ongoing(setup).body.model_dump(by_alias=True),
            "schema": "umi-registration-bridge-policy-body/4",
            "registration_rule": "frozen_uid_hotkey_registration_block/1",
            "registration_snapshot": report["roster"],
        }
    )
    return bridge.sign_registration_bridge_policy(body, wallet=signer)


def test_freeze_preserves_existing_weights_and_signed_round_trip(setup):
    signed = frozen(setup)
    assert (
        decision(signed, setup[0]).expected_row == decision(ongoing(setup), setup[0]).expected_row
    )
    assert bridge.parse_registration_bridge_policy(canonical_json_bytes(signed)) == signed


@pytest.mark.parametrize(
    "changes",
    [
        {"hotkey": hotkey(4000)},
        {"registered_at_block": BLOCK},
        {"hotkey": hotkey(4000), "registered_at_block": BLOCK},
    ],
)
def test_replacement_registration_gets_zero_without_blocking_others(setup, changes):
    signed = frozen(setup)
    obs = replace_participant(setup[0], 71, **changes)
    result = decision(signed, obs)
    assert result.expected_row[71][1] == 0
    assert result.expected_row[6][1] > 0
    assert result.expected_row[72][1] > 0
    assert result.eligible_count == 3


def test_existing_registration_can_recover_health_after_freeze(setup):
    signed = frozen(setup)
    # An existing registration without an endpoint was still in the snapshot.
    obs = replace_participant(setup[0], 10, origin="https://1.0.0.1:443")
    assert decision(signed, obs).expected_row[10][1] > 0


def test_current_permit_still_excludes_snapshot_member_without_aborting(setup):
    obs = replace_participant(setup[0], 71, validator_permit=True)
    row = decision(frozen(setup), obs).expected_row
    assert row[71][1] == 0 and row[6][1] > 0


def test_freeze_requires_new_signature(setup):
    signed = frozen(setup).model_dump(by_alias=True)
    signed["body"]["registration_snapshot"]["participants"][71]["hotkey"] = hotkey(4000)
    with pytest.raises(bridge.RegistrationBridgeError, match="policy_signature_invalid"):
        bridge.parse_registration_bridge_policy(canonical_json_bytes(signed))


def test_future_snapshot_and_duplicate_registration_rejected(setup):
    values = frozen(setup).body.model_dump(by_alias=True)
    values["registration_snapshot"]["finalized_block"] = BLOCK + 1
    with pytest.raises(ValidationError, match="newer than policy"):
        bridge.RegistrationBridgeFrozenPolicyBody.model_validate(values)
    values = frozen(setup).body.model_dump(by_alias=True)
    values["registration_snapshot"]["participants"][1] = values["registration_snapshot"][
        "participants"
    ][0]
    with pytest.raises(ValidationError, match="duplicate UID"):
        bridge.RegistrationBridgeFrozenPolicyBody.model_validate(values)


def test_ongoing_policy_does_not_silently_inherit_freeze(setup):
    obs = replace_participant(setup[0], 71, hotkey=hotkey(4000), registered_at_block=BLOCK - 1)
    assert decision(ongoing(setup), obs).expected_row[71][1] > 0
