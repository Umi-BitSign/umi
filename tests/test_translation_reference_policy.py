"""Real policy signatures; no reference, native proof or chain-live claims."""

import json

import pytest

from umi.crypto import sign_response_digest
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.protocol import canonical_json_bytes
from umi.translation_reference_policy import (
    ApprovedTranslationReferencePolicy,
    SignedTranslationReferencePolicy,
    TranslationReferencePolicy,
    reference_policy_sha256,
    reference_policy_signature_digest,
    verify_reference_policy,
)

from .test_validator_supervisor import _wallets


def case():
    authority, reference, _ = _wallets()
    body = TranslationReferencePolicy(
        schema="umi-translation-reference-policy/1",
        network="finney",
        genesis_hash="0x" + FINNEY_GENESIS_HASH,
        netuid=78,
        mechanism_id=0,
        implementation_profile="umi-certified-reference-follower/1",
        reference_hotkey=reference.hotkey.ss58_address,
        minimum_reference_update_block=1000,
        first_cohort_sequence=5,
        lifetime="until_signed_supersession",
        reference_activity_rule="owned_finalized_epoch_activity/1",
        legacy_recovery_rule="native_reconcile_before_first_new_write/1",
        row_rule="exact_proven_reference_row/1",
    )
    signed = SignedTranslationReferencePolicy(
        schema="umi-signed-translation-reference-policy/1",
        policy=body,
        authority_hotkey=authority.hotkey.ss58_address,
        signature_scheme="sr25519",
        signature=sign_response_digest(authority, reference_policy_signature_digest(body))[1],
    )
    return authority, reference, signed


def test_authenticated_delegation_preserves_explicit_recovery_and_authority_scope():
    authority, _, signed = case()
    result = verify_reference_policy(
        canonical_json_bytes(signed),
        expected_policy_sha256=reference_policy_sha256(signed.policy),
        expected_authority_hotkey=authority.hotkey.ss58_address,
    )
    assert result == signed.policy
    assert not result.arbitrary_transaction_allowed
    assert not result.independent_cohort_certification_claimed
    assert result.legacy_recovery_rule == "native_reconcile_before_first_new_write/1"
    assert not hasattr(result, "chain_submission_authorized")


@pytest.mark.parametrize("change", ["authority", "digest", "body", "signature_domain"])
def test_remote_policy_cannot_select_its_trust_root_or_change_the_reference(change):
    authority, other, signed = case()
    expected = reference_policy_sha256(signed.policy)
    trusted = authority.hotkey.ss58_address
    if change == "authority":
        trusted = other.hotkey.ss58_address
    elif change == "digest":
        expected = "00" * 32
    elif change == "body":
        signed = signed.model_copy(
            update={
                "policy": signed.policy.model_copy(
                    update={"reference_hotkey": authority.hotkey.ss58_address}
                )
            }
        )
    else:
        signed = signed.model_copy(
            update={"signature": sign_response_digest(authority, bytes.fromhex(expected))[1]}
        )
    with pytest.raises(ValueError, match="authenticated release authority"):
        verify_reference_policy(
            canonical_json_bytes(signed),
            expected_policy_sha256=expected,
            expected_authority_hotkey=trusted,
        )


def test_noncanonical_or_broadened_remote_policy_is_rejected():
    authority, _, signed = case()
    kwargs = {
        "expected_policy_sha256": reference_policy_sha256(signed.policy),
        "expected_authority_hotkey": authority.hotkey.ss58_address,
    }
    with pytest.raises(ValueError, match="canonical"):
        verify_reference_policy(
            json.dumps(signed.model_dump(mode="json", by_alias=True)).encode(), **kwargs
        )
    data = signed.model_dump(mode="json", by_alias=True)
    data["policy"]["arbitrary_transaction_allowed"] = True
    with pytest.raises(ValueError):
        verify_reference_policy(canonical_json_bytes(data), **kwargs)


def test_authority_approved_row_policy_has_its_own_signed_domain_and_preserves_v1_reader():
    authority, _, original = case()
    values = original.policy.model_dump(mode="python", by_alias=True)
    values.update(
        schema="umi-translation-reference-policy/2",
        row_rule="exact_proven_and_authority_approved_reference_row/1",
        expected_row_sha256="a" * 64,
    )
    policy = ApprovedTranslationReferencePolicy.model_validate(values)
    signed = original.model_copy(
        update={
            "policy": policy,
            "signature": sign_response_digest(authority, reference_policy_signature_digest(policy))[
                1
            ],
        }
    )
    kwargs = {
        "expected_policy_sha256": reference_policy_sha256(policy),
        "expected_authority_hotkey": authority.hotkey.ss58_address,
    }
    assert verify_reference_policy(canonical_json_bytes(signed), **kwargs) == policy
    altered = signed.model_copy(
        update={"policy": policy.model_copy(update={"expected_row_sha256": "b" * 64})}
    )
    with pytest.raises(ValueError, match="authenticated release authority"):
        verify_reference_policy(canonical_json_bytes(altered), **kwargs)
    assert reference_policy_signature_digest(policy) != reference_policy_signature_digest(
        original.policy
    )
