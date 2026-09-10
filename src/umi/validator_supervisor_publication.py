"""Signed, self-contained publication for a supervised bootstrap result."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .bootstrap_direct_weights import (
    DirectBootstrapCallMaterial,
    DirectBootstrapOperationalPreflight,
    DirectBootstrapSubmissionJournal,
    DirectBootstrapSubmissionReceipt,
    DirectBootstrapTransitionAuthorization,
    OwnerFenceReceipt,
    verify_direct_transition_authorization,
)
from .bootstrap_weights import (
    SignedBootstrapEligibilityManifest,
    verify_signed_bootstrap_eligibility_manifest,
)
from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA = "umi-validator-supervisor-bootstrap-result/1"
SIGNED_SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA = "umi-validator-supervisor-signed-bootstrap-result/1"
SUPERVISOR_BOOTSTRAP_RESULT_SIGNATURE_DOMAIN = b"umi-validator-supervisor-bootstrap-result-v1\0"
MAX_SUPERVISOR_BOOTSTRAP_RESULT_BYTES = 4 * 1024 * 1024


class SupervisorBootstrapResult(StrictProtocolModel):
    """All non-secret records needed to replay one applied bootstrap row."""

    schema_: Literal[SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA] = Field(alias="schema")
    directive_sha256: Hex32
    release_manifest_sha256: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    submission_id: Hex32
    owner_fence_receipt: OwnerFenceReceipt
    signed_manifest: SignedBootstrapEligibilityManifest
    transition_authorization: DirectBootstrapTransitionAuthorization
    drain_checkpoint: DirectBootstrapOperationalPreflight
    call_material: DirectBootstrapCallMaterial
    submission_receipt: DirectBootstrapSubmissionReceipt
    submission_journal: DirectBootstrapSubmissionJournal
    created_at: datetime

    @field_validator("validator_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        authorization = self.transition_authorization
        receipt = self.submission_receipt
        journal = self.submission_journal
        material = self.call_material
        checkpoint_chain = self.drain_checkpoint.chain
        material_chain = material.operational_preflight.chain
        manifest_sha256 = self.signed_manifest.manifest_sha256
        authorization_sha256 = hashlib.sha256(canonical_json_bytes(authorization)).hexdigest()
        material_sha256 = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
        receipt_sha256 = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
        validator = account_id32(self.validator_hotkey)
        fence_preflight = self.owner_fence_receipt.call_material.preflight
        verify_signed_bootstrap_eligibility_manifest(self.signed_manifest)
        verify_direct_transition_authorization(
            self.signed_manifest,
            authorization,
            current_block=receipt.weight_call.block_number,
        )
        if (
            account_id32(authorization.validator_hotkey) != validator
            or account_id32(receipt.validator_hotkey) != validator
            or account_id32(journal.validator_hotkey) != validator
            or authorization.submission_id != self.submission_id
            or journal.submission_id != self.submission_id
            or authorization.manifest_sha256 != manifest_sha256
            or checkpoint_chain.manifest_sha256 != manifest_sha256
            or material.manifest_sha256 != manifest_sha256
            or receipt.manifest_sha256 != manifest_sha256
            or self.drain_checkpoint.signed_manifest != self.signed_manifest
            or checkpoint_chain.transition_authorization != authorization
            or material.operational_preflight.signed_manifest != self.signed_manifest
            or material_chain.transition_authorization != authorization
            or journal.transition_authorization_sha256 != authorization_sha256
            or receipt.call_material_sha256 != material_sha256
            or journal.call_material_sha256 != material_sha256
            or journal.receipt_sha256 != receipt_sha256
            or journal.phase != "applied"
            or receipt.classification != "applied"
            or journal.anchor != receipt.anchor
            or journal.weight_call != receipt.weight_call
            or fence_preflight.netuid != material.netuid
            or fence_preflight.subnet_owner_hotkey_account_id32
            != checkpoint_chain.subnet_owner_hotkey_account_id32
            or fence_preflight.subnet_owner_hotkey_account_id32
            != material_chain.subnet_owner_hotkey_account_id32
            or self.owner_fence_receipt.observation_block > checkpoint_chain.snapshot.block_number
        ):
            raise ValueError("supervisor bootstrap result records are not cross-bound")
        return self


class SignedSupervisorBootstrapResult(StrictProtocolModel):
    """Validator-hotkey signature over one canonical terminal result."""

    schema_: Literal[SIGNED_SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA] = Field(alias="schema")
    result: SupervisorBootstrapResult
    result_sha256: Hex32
    result_digest: Hex32
    signer_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]

    @field_validator("signer_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if (
            account_id32(self.signer_hotkey) != account_id32(self.result.validator_hotkey)
            or not hmac.compare_digest(
                self.result_sha256,
                supervisor_bootstrap_result_sha256(self.result),
            )
            or not hmac.compare_digest(
                self.result_digest,
                supervisor_bootstrap_result_digest(self.result).hex(),
            )
        ):
            raise ValueError("signed supervisor bootstrap result identity is invalid")
        return self


def supervisor_bootstrap_result_digest(result: SupervisorBootstrapResult) -> bytes:
    if not isinstance(result, SupervisorBootstrapResult):
        raise TypeError("result must be a SupervisorBootstrapResult")
    return hashlib.sha256(
        SUPERVISOR_BOOTSTRAP_RESULT_SIGNATURE_DOMAIN + canonical_json_bytes(result)
    ).digest()


def supervisor_bootstrap_result_sha256(result: SupervisorBootstrapResult) -> str:
    if not isinstance(result, SupervisorBootstrapResult):
        raise TypeError("result must be a SupervisorBootstrapResult")
    return hashlib.sha256(canonical_json_bytes(result)).hexdigest()


def sign_supervisor_bootstrap_result(
    result: SupervisorBootstrapResult,
    *,
    wallet: object,
) -> SignedSupervisorBootstrapResult:
    """Sign one fully validated result with its exact validator hotkey."""

    scheme, signature = sign_response_digest(wallet, supervisor_bootstrap_result_digest(result))
    signed = SignedSupervisorBootstrapResult(
        schema=SIGNED_SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA,
        result=result,
        result_sha256=supervisor_bootstrap_result_sha256(result),
        result_digest=supervisor_bootstrap_result_digest(result).hex(),
        signer_hotkey=result.validator_hotkey,
        signature_scheme=scheme,
        signature=signature,
    )
    return verify_signed_supervisor_bootstrap_result(signed)


def verify_signed_supervisor_bootstrap_result(
    signed: SignedSupervisorBootstrapResult,
) -> SignedSupervisorBootstrapResult:
    if not isinstance(signed, SignedSupervisorBootstrapResult):
        raise TypeError("signed must be a SignedSupervisorBootstrapResult")
    if not verify_response_signature(
        supervisor_bootstrap_result_digest(signed.result),
        hotkey_ss58=signed.signer_hotkey,
        scheme=signed.signature_scheme,
        signature=signed.signature,
    ):
        raise ValueError("supervisor bootstrap result signature is invalid")
    return signed


def parse_canonical_signed_supervisor_bootstrap_result(
    payload: bytes,
) -> SignedSupervisorBootstrapResult:
    if not payload or len(payload) > MAX_SUPERVISOR_BOOTSTRAP_RESULT_BYTES:
        raise ValueError("supervisor bootstrap result size is invalid")
    signed = SignedSupervisorBootstrapResult.model_validate_json(payload)
    if canonical_json_bytes(signed) != payload:
        raise ValueError("supervisor bootstrap result is not canonical JSON")
    return verify_signed_supervisor_bootstrap_result(signed)


__all__ = [
    "MAX_SUPERVISOR_BOOTSTRAP_RESULT_BYTES",
    "SIGNED_SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA",
    "SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA",
    "SignedSupervisorBootstrapResult",
    "SupervisorBootstrapResult",
    "parse_canonical_signed_supervisor_bootstrap_result",
    "sign_supervisor_bootstrap_result",
    "supervisor_bootstrap_result_digest",
    "supervisor_bootstrap_result_sha256",
    "verify_signed_supervisor_bootstrap_result",
]
