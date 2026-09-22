"""Forward weight authority for allocations admitted while their round was live.

Historical certificates and scoring deadlines remain unchanged. The authority
permits fresh, short, single-use write leases until replacement or revocation;
it never supplies an operator-selected allocation or an inference outcome.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

import bittensor as bt
from pydantic import Field, model_validator

from .competition_execution import ExecutionBoundary
from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .open_competition import Signature, digest
from .policy import LiveChainObservationPin
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

Block = Annotated[int, Field(ge=1, le=2**53 - 1)]
UNTIL_SUPERSEDED_BLOCK = 2**53 - 1


class RewardContinuityAuthority(StrictProtocolModel):
    schema_: Literal["umi-reward-continuity-authority/1"] = Field(alias="schema")
    policy_sha256: Hex32
    first_round_sha256: Hex32
    first_round_sequence: Block
    last_round_sequence: Block
    release_identity_sha256: Hex32
    chain_pin: LiveChainObservationPin
    network: Literal["finney"] = "finney"
    netuid: Literal[78] = 78
    mechanism_id: Literal[0] = 0
    issued_at_block: Block
    valid_from_block: Block
    lifetime: Literal["until_superseded_or_revoked"]
    allocation_rule: Literal["latest_on_time_certified_exact_projection/1"]
    recipient_change_action: Literal["hold_until_valid_certified_replacement"]
    revocation_rule: Literal["stop_renewal_expire_outstanding_leases/1"]
    admission_authority_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    maximum_write_authorization_blocks: Annotated[int, Field(ge=4, le=100_000)]

    @model_validator(mode="after")
    def bounds(self):
        account_id32(self.admission_authority_hotkey)
        if self.issued_at_block > self.valid_from_block:
            raise ValueError("continuity authority starts before issuance")
        if self.first_round_sequence > self.last_round_sequence:
            raise ValueError("continuity cohort scope is inverted")
        return self


class SignedRewardContinuityAuthority(StrictProtocolModel):
    schema_: Literal["umi-signed-reward-continuity-authority/1"] = Field(alias="schema")
    authority: RewardContinuityAuthority
    signatures: Annotated[list[Signature], Field(min_length=1, max_length=64)]


class CertifiedAllocationAdmission(StrictProtocolModel):
    schema_: Literal["umi-certified-allocation-admission/1"] = Field(alias="schema")
    authority_sha256: Hex32
    package_sha256: Hex32
    settlement_certificate_sha256: Hex32
    round_sha256: Hex32
    round_sequence: Block
    projection_sha256: Hex32
    admitted_at_block: Block
    owned_boundary: ExecutionBoundary


class SignedCertifiedAllocationAdmission(StrictProtocolModel):
    schema_: Literal["umi-signed-certified-allocation-admission/1"] = Field(alias="schema")
    admission: CertifiedAllocationAdmission
    signature: Signature


class RewardContinuation(StrictProtocolModel):
    schema_: Literal["umi-reward-continuation/1"] = Field(alias="schema")
    authority: SignedRewardContinuityAuthority
    admission: SignedCertifiedAllocationAdmission


class RewardContinuityRevocation(StrictProtocolModel):
    schema_: Literal["umi-reward-continuity-revocation/1"] = Field(alias="schema")
    authority_sha256: Hex32
    revoked_at_block: Block
    action: Literal["stop_renewal_expire_outstanding_leases"]


class SignedRewardContinuityRevocation(StrictProtocolModel):
    schema_: Literal["umi-signed-reward-continuity-revocation/1"] = Field(alias="schema")
    revocation: RewardContinuityRevocation
    signatures: Annotated[list[Signature], Field(min_length=1, max_length=64)]


def signature_digest(body):
    return hashlib.sha256(
        b"umi-forward-reward-control-v1\0" + canonical_json_bytes(body)
    ).hexdigest()


def _sign(body, wallet):
    signer = bt.resolve_signer(wallet, role="hotkey")
    scheme, signature = sign_response_digest(wallet, signature_digest(body))
    return Signature(hotkey=signer.ss58_address, scheme=scheme, signature=signature)


def _verify(body, signature):
    if not verify_response_signature(
        signature_digest(body),
        hotkey_ss58=signature.hotkey,
        scheme=signature.scheme,
        signature=signature.signature,
    ):
        raise ValueError("invalid forward reward control signature")


def sign_reward_continuity_authority(authority, wallets):
    authority = RewardContinuityAuthority.model_validate_json(canonical_json_bytes(authority))
    return SignedRewardContinuityAuthority(
        schema="umi-signed-reward-continuity-authority/1",
        authority=authority,
        signatures=list(
            sorted((_sign(authority, w) for w in wallets), key=lambda s: account_id32(s.hotkey))
        ),
    )


def verify_reward_continuity_authority(signed, trusted_hotkeys, *, threshold=1):
    signed = SignedRewardContinuityAuthority.model_validate_json(canonical_json_bytes(signed))
    trusted = {account_id32(k) for k in trusted_hotkeys}
    accounts = [account_id32(s.hotkey) for s in signed.signatures]
    if accounts != sorted(set(accounts)) or not set(accounts) <= trusted:
        raise ValueError("continuity signers are duplicate, unordered or untrusted")
    if len(accounts) < threshold:
        raise ValueError("continuity authority signature threshold not met")
    for signature in signed.signatures:
        _verify(signed.authority, signature)
    if account_id32(signed.authority.admission_authority_hotkey) not in trusted:
        raise ValueError("continuity admission authority is untrusted")
    return signed.authority


def sign_reward_continuity_revocation(revocation, wallets):
    revocation = RewardContinuityRevocation.model_validate_json(canonical_json_bytes(revocation))
    return SignedRewardContinuityRevocation(
        schema="umi-signed-reward-continuity-revocation/1",
        revocation=revocation,
        signatures=sorted(
            (_sign(revocation, w) for w in wallets), key=lambda s: account_id32(s.hotkey)
        ),
    )


def verify_reward_continuity_revocation(signed, authority, trusted_hotkeys, *, threshold, block):
    signed = SignedRewardContinuityRevocation.model_validate_json(canonical_json_bytes(signed))
    accounts = [account_id32(s.hotkey) for s in signed.signatures]
    if (
        signed.revocation.authority_sha256 != digest(authority)
        or not authority.authority.valid_from_block <= signed.revocation.revoked_at_block <= block
        or accounts != sorted(set(accounts))
        or not set(accounts) <= {account_id32(k) for k in trusted_hotkeys}
        or len(accounts) < threshold
    ):
        raise ValueError("invalid continuity revocation authority, time or signature set")
    for signature in signed.signatures:
        _verify(signed.revocation, signature)
    return signed


def _admission_body(authority, package, boundary):
    manifest = package.manifest
    return CertifiedAllocationAdmission(
        schema="umi-certified-allocation-admission/1",
        authority_sha256=digest(authority),
        package_sha256=package.package_sha256,
        settlement_certificate_sha256=manifest.settlement_certificate_sha256,
        round_sha256=manifest.round_sha256,
        round_sequence=manifest.round_sequence,
        projection_sha256=manifest.projection_sha256,
        admitted_at_block=boundary.block,
        owned_boundary=boundary,
    )


def validate_admission_candidate(authority, package, block):
    """Check whether an unadmitted package can enter this authority now."""
    body = authority.authority
    round_ = package.settlement_certificate.publication.round
    if (
        package.manifest.policy_sha256 != body.policy_sha256
        or package.manifest.release_identity_sha256 != body.release_identity_sha256
        or not body.first_round_sequence <= round_.sequence <= body.last_round_sequence
        or (
            round_.sequence == body.first_round_sequence
            and digest(round_) != body.first_round_sha256
        )
    ):
        raise ValueError("continuity admission has different package or cohort bindings")
    # Native package loading already verifies signatures and original evidence
    # timing. First admission additionally requires a current publisher-owned
    # head within the original round. An old claimed observed_block alone is
    # insufficient to admit a certificate first presented after expiry.
    if not (
        max(body.valid_from_block, package.retained_settlement.observed_block)
        <= block
        <= min(round_.valid_through_block, package.policy.valid_through_block)
    ):
        raise ValueError("certificate was not admitted within its original round validity")


def validate_admission(authority, package, admission):
    if admission != _admission_body(authority, package, admission.owned_boundary):
        raise ValueError("continuity admission has different package or cohort bindings")
    validate_admission_candidate(authority, package, admission.admitted_at_block)


def admit_certified_allocation(authority, package, boundary, wallet):
    boundary = ExecutionBoundary.model_validate_json(canonical_json_bytes(boundary))
    admission = _admission_body(authority, package, boundary)
    validate_admission(authority, package, admission)
    signed = SignedCertifiedAllocationAdmission(
        schema="umi-signed-certified-allocation-admission/1",
        admission=admission,
        signature=_sign(admission, wallet),
    )
    if account_id32(signed.signature.hotkey) != account_id32(
        authority.authority.admission_authority_hotkey
    ):
        raise ValueError("wrong certificate admission signer")
    return signed


def verify_reward_continuation(continuation, package, body, trusted_hotkeys, *, threshold=1):
    continuation = RewardContinuation.model_validate_json(canonical_json_bytes(continuation))
    authority = verify_reward_continuity_authority(
        continuation.authority, trusted_hotkeys, threshold=threshold
    )
    signed = continuation.admission
    if account_id32(signed.signature.hotkey) != account_id32(authority.admission_authority_hotkey):
        raise ValueError("unapproved certificate admission signer")
    _verify(signed.admission, signed.signature)
    validate_admission(continuation.authority, package, signed.admission)
    if (
        body.chain_pin != authority.chain_pin
        or body.signed_at_block < signed.admission.admitted_at_block
        or body.valid_through_block - body.signed_at_block
        > authority.maximum_write_authorization_blocks
    ):
        raise ValueError("write authorization exceeds forward continuity authority")
    return authority
