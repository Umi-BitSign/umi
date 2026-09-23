"""Original root consent and explicit one-transition historical compatibility.

Compatibility signatures authorize verification/recovery of preserved history.
They never relabel old packages as a new release or authorize old sends.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_serializer, model_validator
from typing_extensions import Self

from .competition_reward_continuity import UNTIL_SUPERSEDED_BLOCK
from .crypto import verify_response_signature
from .encoding import account_id32
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import (
    MAX_JSON_SAFE_INTEGER,
    SupervisorDirectiveSignature,
    ValidatorSupervisorConfig,
)

_MODE_ORDER = ("competition_replay", "competition_weights")
CONSENT_DOMAIN = b"umi-validator-supervisor-operator-consent-v1\0"
HISTORY_DOMAIN = b"umi-successor-history-compatibility-v1\0"


class OriginalSuccessorConsent(StrictProtocolModel):
    """Root-owned local consent that narrows signed successor authority.

    The host loader must establish file ownership, mode, and exact bytes. This
    record contains no authority keys and cannot replace the v3 trust policy.
    """

    schema_: Literal["umi-validator-supervisor-operator-consent/1"] = Field(alias="schema")
    source_config_sha256: Hex32
    channel_id: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    predecessor_sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    predecessor_directive_sha256: Hex32
    predecessor_signed_directive_sha256: Hex32
    predecessor_accepted_at_finalized_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    approved_host_manifest_sha256: Hex32
    target_platform: Literal["linux/amd64", "linux/arm64"]
    allowed_modes: Annotated[
        list[Literal["competition_replay", "competition_weights"]],
        Field(min_length=1, max_length=2),
    ]
    required_recovery_profile: Literal["stopped_bootstrap_recovery/1"]
    authorized_at_finalized_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    valid_through_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]

    reward_continuity_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def preserve_original_consent(self, handler):
        value = handler(self)
        if self.reward_continuity_sha256 is None:
            value.pop("reward_continuity_sha256", None)
        return value

    @field_validator("validator_hotkey")
    @classmethod
    def validate_validator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_consent(self) -> Self:
        if (
            self.reward_continuity_sha256 is not None
            and self.valid_through_block != UNTIL_SUPERSEDED_BLOCK
        ):
            raise ValueError("continuity consent requires explicit until-superseded lifetime")
        expected = [mode for mode in _MODE_ORDER if mode in self.allowed_modes]
        if self.allowed_modes != expected:
            raise ValueError("successor consent modes must be unique and canonically ordered")
        if self.valid_through_block < self.authorized_at_finalized_block:
            raise ValueError("successor operator consent interval is inverted")
        if self.authorized_at_finalized_block < self.predecessor_accepted_at_finalized_block:
            raise ValueError("successor consent predates its predecessor observation")
        return self


def original_consent_digest(consent: OriginalSuccessorConsent) -> str:
    return hashlib.sha256(CONSENT_DOMAIN + canonical_json_bytes(consent)).hexdigest()


def transition_target_consent(consent) -> OriginalSuccessorConsent:
    """The new local consent fields, without embedding a signature of itself."""
    value = consent.model_dump(by_alias=True, mode="json")
    value.pop("historical_consent", None)
    value.pop("history_compatibility", None)
    value["schema"] = "umi-validator-supervisor-operator-consent/1"
    return OriginalSuccessorConsent.model_validate(value)


class HistoryCompatibilityBody(StrictProtocolModel):
    schema_: Literal["umi-successor-history-compatibility/1"] = Field(alias="schema")
    source_config_sha256: Hex32
    channel_id: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    target_platform: Literal["linux/amd64", "linux/arm64"]
    network: Literal["finney"] = "finney"
    netuid: Literal[78] = 78
    mechanism_id: Literal[0] = 0
    chain_pin_sha256: Hex32
    original_consent_sha256: Hex32
    target_consent_sha256: Hex32
    original_installation_receipt_sha256: Hex32
    original_host_manifest_sha256: Hex32
    target_host_manifest_sha256: Hex32
    original_worker_limits_sha256: Hex32
    target_worker_limits_sha256: Hex32
    original_checkpoint_sha256: Hex32
    retained_history_sha256: Hex32
    predecessor_state_sha256: Hex32
    predecessor_sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER - 1)]
    predecessor_directive_sha256: Hex32
    predecessor_accepted_at_finalized_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    original_release_identity_sha256s: Annotated[list[Hex32], Field(min_length=1, max_length=16)]
    target_release_identity_sha256: Hex32
    target_oci_manifest_sha256: Hex32
    target_source_tree_sha256: Hex32
    target_storage_config_sha256: Hex32
    first_round_sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    last_round_sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    forward_policy_sha256s: Annotated[list[Hex32], Field(min_length=1, max_length=32)]
    migration_valid_from_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    migration_valid_through_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    minimum_transition_headroom_blocks: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    historical_use: Literal["verification_and_stopped_recovery_only"]
    old_release_new_sends_allowed: Literal[False] = False

    @model_validator(mode="after")
    def bounds(self) -> Self:
        account_id32(self.validator_hotkey)
        for values in (self.original_release_identity_sha256s, self.forward_policy_sha256s):
            if values != sorted(set(values)):
                raise ValueError("compatibility identity lists must be unique and sorted")
        if (
            self.original_host_manifest_sha256 == self.target_host_manifest_sha256
            or self.target_release_identity_sha256 in self.original_release_identity_sha256s
            or self.last_round_sequence < self.first_round_sequence
            or self.migration_valid_through_block < self.migration_valid_from_block
        ):
            raise ValueError("compatibility must describe one forward runtime transition")
        return self


def history_compatibility_digest(body: HistoryCompatibilityBody) -> bytes:
    return hashlib.sha256(HISTORY_DOMAIN + canonical_json_bytes(body)).digest()


class SignedHistoryCompatibility(StrictProtocolModel):
    schema_: Literal["umi-signed-successor-history-compatibility/1"] = Field(alias="schema")
    body: HistoryCompatibilityBody
    body_sha256: Hex32
    signatures: Annotated[list[SupervisorDirectiveSignature], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def digest_and_signers(self) -> Self:
        if self.body_sha256 != hashlib.sha256(canonical_json_bytes(self.body)).hexdigest():
            raise ValueError("history compatibility body digest mismatch")
        accounts = [account_id32(item.hotkey) for item in self.signatures]
        if accounts != sorted(set(accounts)):
            raise ValueError("history compatibility signers must be unique and account-sorted")
        return self


def validate_consent_transition(target, original, body: HistoryCompatibilityBody) -> None:
    if (
        original_consent_digest(original) != body.original_consent_sha256
        or original_consent_digest(transition_target_consent(target)) != body.target_consent_sha256
        or original.approved_host_manifest_sha256 != body.original_host_manifest_sha256
        or target.approved_host_manifest_sha256 != body.target_host_manifest_sha256
    ):
        raise ValueError("history compatibility consent binding mismatch")
    for name in (
        "source_config_sha256",
        "channel_id",
        "validator_hotkey",
        "target_platform",
        "predecessor_sequence",
        "predecessor_directive_sha256",
        "predecessor_signed_directive_sha256",
        "predecessor_accepted_at_finalized_block",
        "required_recovery_profile",
    ):
        if getattr(original, name) != getattr(target, name):
            raise ValueError("migration cannot rewrite the original installation anchor")
    if (
        target.source_config_sha256 != body.source_config_sha256
        or target.channel_id != body.channel_id
        or target.validator_hotkey != body.validator_hotkey
        or target.target_platform != body.target_platform
        or not body.migration_valid_from_block
        <= target.authorized_at_finalized_block
        <= body.migration_valid_through_block
    ):
        raise ValueError("history compatibility target scope mismatch")


def verify_history_compatibility(
    signed, *, config: ValidatorSupervisorConfig
) -> HistoryCompatibilityBody:
    # Reject model_construct / post-validation mutation at every trust boundary.
    signed = SignedHistoryCompatibility.model_validate_json(
        canonical_json_bytes(signed), strict=True
    )
    body = signed.body
    if (
        body.source_config_sha256 != hashlib.sha256(canonical_json_bytes(config)).hexdigest()
        or body.channel_id != config.channel_id
        or account_id32(body.validator_hotkey) != account_id32(config.validator_hotkey)
        or body.target_platform != config.target_platform
    ):
        raise ValueError("history compatibility differs from installed trust scope")
    authorities = {account_id32(item.hotkey): item for item in config.trusted_authorities}
    verified = set()
    for signature in signed.signatures:
        account = account_id32(signature.hotkey)
        authority = authorities.get(account)
        if authority is None or authority.signature_scheme != signature.signature_scheme:
            raise ValueError("history compatibility signer is not a trusted authority")
        if not verify_response_signature(
            history_compatibility_digest(body),
            hotkey_ss58=authority.hotkey,
            scheme=authority.signature_scheme,
            signature=signature.signature,
        ):
            raise ValueError("history compatibility signature invalid")
        verified.add(account)
    if len(verified) < config.signature_threshold:
        raise ValueError("history compatibility quorum incomplete")
    return body
