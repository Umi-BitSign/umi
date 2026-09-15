# Imported pytest fixtures are injected into same-named test parameters.
# ruff: noqa: F811
import asyncio

import pytest
from pydantic import ValidationError

import umi.registration_bridge as bridge
from tests.test_registration_bridge import decision
from tests.test_registration_bridge_funding import setup  # noqa: F401
from tests.test_registration_bridge_runtime import wallet  # noqa: F401
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor_adapters import (
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_BUNDLE_SCHEMA,
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
    _parse_bootstrap_input_bundle,
)


def ongoing(setup):
    _, _, signer, previous, _ = setup
    body = bridge.RegistrationBridgeOngoingPolicyBody.model_validate(
        {
            **previous.body.model_dump(by_alias=True),
            "schema": "umi-registration-bridge-policy-body/3",
            "lifetime": "until_superseded",
            "stop_submitting_block": None,
            "hard_sunset_block": None,
        }
    )
    return bridge.sign_registration_bridge_policy(body, wallet=signer)


@pytest.mark.parametrize("block", [9073731, 9075171, 10_000_000, 100_000_000])
def test_ongoing_policy_submits_past_legacy_sunset_with_same_allocation(setup, block):
    obs, _, _, previous, _ = setup
    signed = ongoing(setup)
    raw = canonical_json_bytes(signed)
    parsed = bridge.parse_registration_bridge_policy(raw)
    assert canonical_json_bytes(parsed) == raw
    assert parsed.body.funding_snapshot == previous.body.funding_snapshot
    assert parsed.body.stop_submitting_block is None
    assert parsed.body.hard_sunset_block is None
    late = obs.model_copy(update={"block_number": block})
    result = decision(parsed, late)
    assert result.action == "submit"
    assert result.expected_row == decision(previous, obs).expected_row
    bridge._validate_directive_interval(
        parsed, parsed.body.valid_from_block, bridge.MAX_JSON_INTEGER
    )
    bundle = canonical_json_bytes(
        {
            "schema": SUPERVISOR_REGISTRATION_BRIDGE_INPUT_BUNDLE_SCHEMA,
            "profile": SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
            "signed_policy": parsed.model_dump(by_alias=True),
        }
    )
    assert _parse_bootstrap_input_bundle(bundle).signed_policy == parsed


def test_lifetime_change_requires_new_signature(setup):
    raw = setup[3].model_dump(by_alias=True)
    raw["body"].update(
        schema="umi-registration-bridge-policy-body/3",
        lifetime="until_superseded",
        stop_submitting_block=None,
        hard_sunset_block=None,
    )
    with pytest.raises(bridge.RegistrationBridgeError, match="policy_signature_invalid"):
        bridge.parse_registration_bridge_policy(canonical_json_bytes(raw))


def test_legacy_policy_still_expires_and_cannot_omit_cutoffs(setup):
    old = setup[3]
    with pytest.raises(bridge.RegistrationBridgeError, match="policy_inactive"):
        bridge.verify_registration_bridge_policy(
            old, expected_revision=old.body.umi_git_revision, current_block=9075171
        )
    values = old.body.model_dump(by_alias=True)
    values.update(stop_submitting_block=None, hard_sunset_block=None)
    with pytest.raises(ValidationError):
        bridge.RegistrationBridgeFundingPolicyBody.model_validate(values)


def test_ongoing_policy_requires_explicit_lifetime_and_null_cutoffs(setup):
    values = ongoing(setup).body.model_dump(by_alias=True)
    for field, value in (
        ("lifetime", "temporary"),
        ("stop_submitting_block", 9073731),
        ("hard_sunset_block", 9075171),
    ):
        with pytest.raises(ValidationError):
            bridge.RegistrationBridgeOngoingPolicyBody.model_validate({**values, field: value})


@pytest.mark.parametrize("directive_end", [bridge.MAX_JSON_INTEGER, 10_000_010])
def test_ongoing_runtime_receipt_and_directive_stop(
    setup, wallet, tmp_path, monkeypatch, directive_end
):
    import tests.test_registration_bridge_runtime as runtime

    block = 10_000_000
    monkeypatch.setattr(runtime, "BLOCK", block)
    signed = ongoing(setup)
    before = runtime.writer_observation(wallet, block_number=block)
    after = runtime.applied_observation(wallet, signed, block=block + 1)
    with bridge.RegistrationBridgeState(tmp_path / "state") as state:
        chain = runtime.Chain(state, [before, before, after])
        result = asyncio.run(
            bridge.run_registration_bridge_iteration(
                signed,
                wallet=wallet,
                chain=chain,
                state=state,
                expected_revision=runtime.REVISION,
                directive_valid_from=signed.body.valid_from_block,
                directive_valid_through=directive_end,
                request=runtime.healthy,
            )
        )
        if directive_end == bridge.MAX_JSON_INTEGER:
            assert result["status"] == "submitted"
            assert state.load().phase == "applied"
            assert state.load().weight_call.block_number == block + 1
            assert len(chain.client.calls) == 1
        else:
            assert result["reason_code"] == "submission_cutoff_reached"
            assert not chain.client.calls
