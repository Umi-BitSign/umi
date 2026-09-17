"""Signed bridge policy contracts and signature verification."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal

import bittensor as bt
from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from ..crypto import sign_response_digest, verify_response_signature
from ..encoding import account_id32
from ..grandpa_finality import FINNEY_GENESIS_HASH
from ..protocol import StrictProtocolModel, canonical_json_bytes
from ..registration_funding_audit import FundingRoster
from ..registration_funding_snapshot import FundingSnapshot

REGISTRATION_BRIDGE_PROFILE = "umi-registration-bridge-validator/1"

REGISTRATION_BRIDGE_POLICY_BODY_SCHEMA = "umi-registration-bridge-policy-body/1"

REGISTRATION_BRIDGE_POLICY_SCHEMA = "umi-registration-bridge-policy/1"

REGISTRATION_BRIDGE_SIGNATURE_DOMAIN = b"umi-registration-bridge-policy-v1\0"

REGISTRATION_BRIDGE_COORDINATOR = "5GsPXiSyzpK3rRoeAmjT4F5Cqa1RmP1CyBvNpwNDsDejyNZ4"

REGISTRATION_BRIDGE_STOP_SUBMITTING_BLOCK = 9_073_731

REGISTRATION_BRIDGE_HARD_SUNSET_BLOCK = 9_075_171

MAX_JSON_INTEGER = 2**53 - 1

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024

UInt = Annotated[int, Field(ge=0, le=MAX_JSON_INTEGER)]

PositiveInt = Annotated[int, Field(gt=0, le=MAX_JSON_INTEGER)]


class RegistrationBridgeError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise RegistrationBridgeError(reason)


class RegistrationBridgePolicyBody(StrictProtocolModel):
    schema_: Literal[REGISTRATION_BRIDGE_POLICY_BODY_SCHEMA] = Field(alias="schema")
    profile: Literal[REGISTRATION_BRIDGE_PROFILE]
    coordinator_hotkey: str
    network: Literal["finney"]
    genesis_hash: Literal[f"0x{FINNEY_GENESIS_HASH}"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    valid_from_block: PositiveInt
    stop_submitting_block: Literal[REGISTRATION_BRIDGE_STOP_SUBMITTING_BLOCK]
    hard_sunset_block: Literal[REGISTRATION_BRIDGE_HARD_SUNSET_BLOCK]
    reward_rule: Literal["equal_live_coldkey_groups/1", "equal_live_coldkey_ip_groups/1"]
    grouping_rule: Literal[
        "registered_hotkey_owner_account_id32/1",
        "registered_owner_or_https_ip_connected_components/1",
    ]
    allocation_rule: Literal["equal_group_budget_min_size_divmod_uid_order/1"]
    exclude_uid_zero: Literal[True]
    exclude_validator_permits: Literal[True]
    exclude_subnet_owner_hotkeys: Literal[True]
    require_validator_permit: Literal[True]
    require_registration_before_submission: Literal[True]
    require_public_pilot_replay: Literal[False]
    require_fresh_endpoint_health: Literal[True]
    require_public_ip_https_axon: Literal[True]
    health_path: Literal["/healthz"]
    health_status_code: Literal[200]
    health_timeout_seconds: Literal[5]
    health_batch_timeout_seconds: Literal[90]
    health_concurrency: Literal[16]
    health_maximum_body_bytes: Literal[16_384]
    health_ttl_seconds: Literal[120]
    tls_verification: Literal["system_trust_store/1"]
    allow_redirects: Literal[False]
    maximum_raw_weight: Literal[65_535]
    # Retain the legacy field and its signed bytes for existing policies/journals.
    # Runtime specVersion is informational; compatibility is checked from the
    # finalized chain settings and decoded state, not a runtime-number allowlist.
    required_runtime_spec_version: Annotated[int, Field(ge=0, le=2**32 - 1)]
    required_mechanism_count: Literal[1]
    required_commit_reveal_enabled: Literal[False]
    required_commit_reveal_version: Literal[4]
    required_reveal_period_epochs: Literal[1]
    weights_version_key: Literal[4_294_967_296]
    required_tempo: Literal[360]
    required_activity_cutoff_factor_milli: Literal[1000]
    required_activity_cutoff_blocks: Literal[360]
    required_weights_set_rate_limit: Literal[100]
    required_min_allowed_weights: Literal[256]
    required_max_allowed_uids: Literal[256]
    maximum_finalized_age_seconds: Literal[120]
    refresh_margin_blocks: Literal[120]
    submission_era_period: Literal[8]
    submission_timeout_seconds: Literal[60]
    submission_headroom_blocks: Literal[64]

    @property
    def submission_limit(self) -> int:
        return (
            self.stop_submitting_block
            if self.stop_submitting_block is not None
            else MAX_JSON_INTEGER + 1
        )

    @property
    def sunset_limit(self) -> int:
        return (
            self.hard_sunset_block if self.hard_sunset_block is not None else MAX_JSON_INTEGER + 1
        )

    @field_validator("coordinator_hotkey")
    @classmethod
    def authority(cls, value: str) -> str:
        account_id32(value)
        if value != REGISTRATION_BRIDGE_COORDINATOR:
            raise ValueError("registration bridge authority is not the UMI coordinator")
        return value

    @model_validator(mode="after")
    def interval(self) -> Self:
        if self.valid_from_block + self.submission_headroom_blocks >= self.submission_limit:
            raise ValueError("registration bridge has no submission interval")
        expected_grouping = {
            "equal_live_coldkey_groups/1": "registered_hotkey_owner_account_id32/1",
            "equal_live_coldkey_ip_groups/1": "registered_owner_or_https_ip_connected_components/1",
            "equal_live_coldkey_ip_funder_groups/1": (
                "registered_owner_or_https_ip_or_recorded_funder_connected_components/1"
            ),
        }[self.reward_rule]
        if self.grouping_rule != expected_grouping:
            raise ValueError("registration bridge reward and grouping rules disagree")
        return self


class RegistrationBridgeFundingPolicyBody(RegistrationBridgePolicyBody):
    schema_: Literal["umi-registration-bridge-policy-body/2"] = Field(alias="schema")
    reward_rule: Literal["equal_live_coldkey_ip_funder_groups/1"]
    grouping_rule: Literal["registered_owner_or_https_ip_or_recorded_funder_connected_components/1"]
    funding_snapshot: FundingSnapshot

    @model_validator(mode="after")
    def funding_interval(self) -> Self:
        if self.funding_snapshot.finalized_block > self.valid_from_block:
            raise ValueError("funding snapshot is newer than policy")
        return self


class RegistrationBridgeOngoingPolicyBody(RegistrationBridgeFundingPolicyBody):
    """Explicitly authorized bridge with no scheduled expiry.

    A signed successor directive or operator stop still retires its writer.
    Historical v1/v2 policies retain their exact signed expiry semantics.
    """

    schema_: Literal["umi-registration-bridge-policy-body/3"] = Field(alias="schema")
    lifetime: Literal["until_superseded"]
    stop_submitting_block: None
    hard_sunset_block: None


class RegistrationBridgeFrozenPolicyBody(RegistrationBridgeOngoingPolicyBody):
    """Keep bridge eligibility within one signed finalized registration roster."""

    schema_: Literal["umi-registration-bridge-policy-body/4"] = Field(alias="schema")
    registration_rule: Literal["frozen_uid_hotkey_registration_block/1"]
    registration_snapshot: FundingRoster

    @model_validator(mode="after")
    def registration_interval(self) -> Self:
        if self.registration_snapshot.finalized_block > self.valid_from_block:
            raise ValueError("registration snapshot is newer than policy")
        if [p.uid for p in self.registration_snapshot.participants] != list(range(256)):
            raise ValueError("registration snapshot must contain the ordered full UID domain")
        return self


class SignedRegistrationBridgePolicy(StrictProtocolModel):
    schema_: Literal[REGISTRATION_BRIDGE_POLICY_SCHEMA] = Field(alias="schema")
    body: Annotated[
        RegistrationBridgePolicyBody
        | RegistrationBridgeFundingPolicyBody
        | RegistrationBridgeOngoingPolicyBody
        | RegistrationBridgeFrozenPolicyBody,
        Field(discriminator="schema_"),
    ]
    signature_scheme: Literal["sr25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]


def registration_bridge_policy_digest(body: RegistrationBridgePolicyBody) -> bytes:
    body = type(body).model_validate(body.model_dump(mode="python", by_alias=True))
    return hashlib.sha256(
        REGISTRATION_BRIDGE_SIGNATURE_DOMAIN + canonical_json_bytes(body)
    ).digest()


def registration_bridge_policy_sha256(signed: SignedRegistrationBridgePolicy) -> str:
    return hashlib.sha256(canonical_json_bytes(signed)).hexdigest()


def verify_registration_bridge_policy(
    signed: SignedRegistrationBridgePolicy, *, expected_revision: str, current_block: int
) -> SignedRegistrationBridgePolicy:
    signed = SignedRegistrationBridgePolicy.model_validate(
        signed.model_dump(mode="python", by_alias=True)
    )
    _require(type(current_block) is int, "policy_block_invalid")
    _require(signed.body.umi_git_revision == expected_revision, "policy_revision_mismatch")
    _require(
        signed.body.valid_from_block <= current_block < signed.body.sunset_limit,
        "policy_inactive",
    )
    _require(
        verify_response_signature(
            registration_bridge_policy_digest(signed.body),
            hotkey_ss58=signed.body.coordinator_hotkey,
            scheme=signed.signature_scheme,
            signature=signed.signature,
        ),
        "policy_signature_invalid",
    )
    return signed


def parse_registration_bridge_policy(payload: bytes) -> SignedRegistrationBridgePolicy:
    _canonical_object(payload)
    signed = SignedRegistrationBridgePolicy.model_validate_json(payload)
    _require(canonical_json_bytes(signed) == payload, "policy_noncanonical")
    return verify_registration_bridge_policy(
        signed,
        expected_revision=signed.body.umi_git_revision,
        current_block=signed.body.valid_from_block,
    )


def sign_registration_bridge_policy(
    body: RegistrationBridgePolicyBody, *, wallet: Any
) -> SignedRegistrationBridgePolicy:
    signer = bt.resolve_signer(wallet, role="hotkey")
    _require(signer.ss58_address == body.coordinator_hotkey, "policy_signer_mismatch")
    scheme, signature = sign_response_digest(wallet, registration_bridge_policy_digest(body))
    return verify_registration_bridge_policy(
        SignedRegistrationBridgePolicy(
            schema=REGISTRATION_BRIDGE_POLICY_SCHEMA,
            body=body,
            signature_scheme=scheme,
            signature=signature,
        ),
        expected_revision=body.umi_git_revision,
        current_block=body.valid_from_block,
    )


def _canonical_object(payload: bytes):
    _require(type(payload) is bytes and 0 < len(payload) <= MAX_DOCUMENT_BYTES, "document_size")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            _require(key not in value, "document_duplicate_key")
            value[key] = item
        return value

    value = json.loads(payload, object_pairs_hook=unique)
    _require(
        isinstance(value, dict) and canonical_json_bytes(value) == payload, "document_noncanonical"
    )
    return value
