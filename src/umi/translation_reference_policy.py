"""Signed delegation for the legacy supervisor's fixed translation profile.

A reference follower is not an independent cohort certifier or a standing-series
member. The original native reference writer retains those responsibilities.
The worker must still prove the reference's current hotkey, permit, epoch
activity and full row, reconcile its own legacy journal and collect its own
fresh signing/nonce proofs. This module grants none of those capabilities.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field

from .crypto import verify_response_signature
from .encoding import account_id32
from .grandpa_finality import FINNEY_GENESIS_HASH
from .open_competition import Hotkey
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_REFERENCE_POLICY_BYTES = 16 * 1024
REFERENCE_POLICY_DOMAIN = b"umi-translation-reference-policy-v1\0"
APPROVED_REFERENCE_POLICY_DOMAIN = b"umi-translation-reference-policy-v2\0"


class TranslationReferencePolicy(StrictProtocolModel):
    schema_: Literal["umi-translation-reference-policy/1"] = Field(alias="schema")
    network: Literal["finney"]
    genesis_hash: Literal[f"0x{FINNEY_GENESIS_HASH}"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    implementation_profile: Literal["umi-certified-reference-follower/1"]
    reference_hotkey: Hotkey
    minimum_reference_update_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    first_cohort_sequence: Annotated[int, Field(ge=1, le=2**32 - 1)]
    lifetime: Literal["until_signed_supersession"]
    reference_activity_rule: Literal["owned_finalized_epoch_activity/1"]
    legacy_recovery_rule: Literal["native_reconcile_before_first_new_write/1"]
    row_rule: Literal["exact_proven_reference_row/1"]
    maximum_finalized_age_seconds: Literal[120] = 120
    refresh_margin_blocks: Literal[120] = 120
    submission_era_period: Literal[8] = 8
    submission_timeout_seconds: Literal[60] = 60
    arbitrary_transaction_allowed: Literal[False] = False
    independent_cohort_certification_claimed: Literal[False] = False


class ApprovedTranslationReferencePolicy(TranslationReferencePolicy):
    """The fixed writer requires an authority-approved allocation as well.

    A proven on-chain reference row establishes what that hotkey wrote, not
    independent cohort certification. The existing release authority separately
    approves its exact UID allocation. A successor cohort gets another signed
    policy through the same automatic directive channel, without a new image.
    """

    schema_: Literal["umi-translation-reference-policy/2"] = Field(alias="schema")
    row_rule: Literal["exact_proven_and_authority_approved_reference_row/1"]
    expected_row_sha256: Hex32


def _reparse_policy(policy):
    if type(policy) not in (TranslationReferencePolicy, ApprovedTranslationReferencePolicy):
        raise ValueError("reference policy has an unsupported native type")
    return type(policy).model_validate_json(canonical_json_bytes(policy))


class SignedTranslationReferencePolicy(StrictProtocolModel):
    schema_: Literal["umi-signed-translation-reference-policy/1"] = Field(alias="schema")
    policy: Annotated[
        TranslationReferencePolicy | ApprovedTranslationReferencePolicy,
        Field(discriminator="schema_"),
    ]
    authority_hotkey: Hotkey
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: str


def reference_policy_sha256(policy: TranslationReferencePolicy) -> str:
    policy = _reparse_policy(policy)
    return hashlib.sha256(canonical_json_bytes(policy)).hexdigest()


def reference_policy_signature_digest(policy: TranslationReferencePolicy) -> bytes:
    policy = _reparse_policy(policy)
    domain = (
        APPROVED_REFERENCE_POLICY_DOMAIN
        if type(policy) is ApprovedTranslationReferencePolicy
        else REFERENCE_POLICY_DOMAIN
    )
    return hashlib.sha256(domain + canonical_json_bytes(policy)).digest()


def parse_reference_policy(payload: bytes) -> SignedTranslationReferencePolicy:
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_REFERENCE_POLICY_BYTES:
        raise ValueError("reference policy is missing or exceeds its typed control bound")
    signed = SignedTranslationReferencePolicy.model_validate_json(payload)
    if canonical_json_bytes(signed) != payload:
        raise ValueError("reference policy must retain its canonical signed bytes")
    return signed


def verify_reference_policy(
    payload: bytes, *, expected_policy_sha256: str, expected_authority_hotkey: str
) -> TranslationReferencePolicy:
    """Use the authority and policy identity from the authenticated release.

    A caller-supplied remote key is not a trust root. The fixed worker's release
    envelope must supply these expectations before any reference is contacted.
    Successful verification delegates the named reference only; it never proves
    current selection, reference liveness, local journal recovery or a nonce.
    """
    signed = parse_reference_policy(payload)
    if (
        reference_policy_sha256(signed.policy) != expected_policy_sha256
        or account_id32(signed.authority_hotkey) != account_id32(expected_authority_hotkey)
        or not verify_response_signature(
            reference_policy_signature_digest(signed.policy),
            hotkey_ss58=expected_authority_hotkey,
            scheme=signed.signature_scheme,
            signature=signed.signature,
        )
    ):
        raise ValueError("reference policy differs from the authenticated release authority")
    return signed.policy
