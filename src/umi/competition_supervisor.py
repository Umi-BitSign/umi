"""Signed v4 supervisor contracts for competition replay and weight activation.

This module defines data and verification rules. It does not stop a service,
load a wallet, stage an image, mount a path, run a command, contact a chain, or
submit weights. A signed directive selects one of two fixed worker profiles.
The host adapter owns the fixed command and mount table for those profiles.

The first v4 directive extends an exact retained v3 directive. Its sequence and
predecessor continue the existing high-water mark. The old signed bytes are
parsed and verified by the v3 implementation under the v3 signature domain.
They are never decoded as a v4 record.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .competition_package import (
    CompetitionPackageLimits,
    CompetitionReleaseIdentity,
    VerifiedCompetitionPackage,
    competition_release_identity_digest,
    load_competition_package,
)
from .competition_weights import (
    CompetitionWeightAuthorizationBody,
    SignedCompetitionWeightAuthorization,
    verify_competition_weight_authorization,
)
from .crypto import verify_response_signature
from .encoding import account_id32
from .policy import LiveChainObservationPin
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import (
    MAX_JSON_SAFE_INTEGER,
    MAX_SUPERVISOR_AUTHORITIES,
    MAX_SUPERVISOR_DIRECTIVES_PER_PAGE,
    MAX_SUPERVISOR_RELEASE_BUNDLE_BYTES,
    MAX_SUPERVISOR_VALIDATORS,
    SupervisorDirectiveSignature,
    SupervisorDirectiveState,
    ValidatorSupervisorConfig,
    ValidatorSupervisorError,
    advance_supervisor_directive_history_state,
    parse_canonical_signed_supervisor_directive,
)

SUCCESSOR_SUPERVISOR_DIRECTIVE_SCHEMA = "umi-validator-supervisor-directive/4"
SUCCESSOR_SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA = "umi-validator-supervisor-signed-directive/4"
SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA = "umi-validator-supervisor-directive-page/4"
SUCCESSOR_SUPERVISOR_DIRECTIVE_STATE_SCHEMA = "umi-validator-supervisor-directive-state/4"
SUCCESSOR_SUPERVISOR_OPERATOR_CONSENT_SCHEMA = "umi-validator-supervisor-operator-consent/1"
SUCCESSOR_REPLAY_PACKAGE_TARGET_SCHEMA = "umi-successor-replay-package-target/1"
SUCCESSOR_CHAIN_AUTHORIZATION_TARGET_SCHEMA = "umi-successor-chain-authorization-target/1"
SUCCESSOR_WORKER_CAPABILITIES_SCHEMA = "umi-successor-worker-capabilities/1"
SUCCESSOR_RELEASE_TARGET_SCHEMA = "umi-successor-supervisor-release-target/1"
SUCCESSOR_CHAIN_TARGET_SCHEMA = "umi-successor-supervisor-chain-target/1"

SUCCESSOR_SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN = b"umi-validator-supervisor-directive-v4\0"
SUCCESSOR_OPERATOR_CONSENT_DOMAIN = b"umi-validator-supervisor-operator-consent-v1\0"
MAX_SUCCESSOR_DOCUMENT_BYTES = 1024 * 1024
MAX_SUCCESSOR_CHAIN_AUTHORIZATION_BYTES = 4 * 1024 * 1024
MIN_SUCCESSOR_ACTIVATION_HEADROOM_BLOCKS = 2
MAX_SUCCESSOR_ACTIVATION_HEADROOM_BLOCKS = 100_000
SUCCESSOR_STATE_SCHEMA_VERSION = 4

SuccessorSupervisorMode = Literal["hold", "competition_replay", "competition_weights"]
SuccessorValidatorScope = Literal["explicit_hotkeys", "any_permitted_sn78"]
SuccessorEntrypointProfile = Literal[
    "umi-competition-replay-worker/1",
    "umi-competition-weight-worker/1",
]
SuccessorPredecessorVersion = Literal[3, 4]

_OCI_REPOSITORY_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?"
    r"(?::[1-9][0-9]{0,4})?"
    r"/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
_GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_TARGET_TRIPLE = {
    "linux/amd64": "x86_64-unknown-linux-gnu",
    "linux/arm64": "aarch64-unknown-linux-gnu",
}
_MODE_ORDER = ("competition_replay", "competition_weights")
_ModelT = TypeVar("_ModelT", bound=StrictProtocolModel)


class SuccessorWorkerCapabilities(StrictProtocolModel):
    """Fixed worker access; Finney clients are pinned application endpoints."""

    """Fixed host capabilities selected by a signed worker mode."""

    schema_: Literal[SUCCESSOR_WORKER_CAPABILITIES_SCHEMA] = Field(alias="schema")
    package_access: Literal["read_only"] = "read_only"
    wallet_access: Literal["none", "configured_validator_hotkey_read_only"]
    network_access: Literal["none", "finney_clients"]
    chain_submission: bool
    arbitrary_command_allowed: Literal[False] = False
    arbitrary_mount_allowed: Literal[False] = False


class SuccessorSupervisorChainTarget(StrictProtocolModel):
    """Immutable chain family required by the worker and its authorization."""

    schema_: Literal[SUCCESSOR_CHAIN_TARGET_SCHEMA] = Field(alias="schema")
    network: Literal["finney"] = "finney"
    netuid: Literal[78] = 78
    mechanism_id: Literal[0] = 0
    chain_pin: LiveChainObservationPin

    @model_validator(mode="after")
    def bind_network(self) -> Self:
        if self.chain_pin.network != self.network:
            raise ValueError("successor chain target and runtime pin disagree")
        return self


class SuccessorSupervisorReleaseTarget(StrictProtocolModel):
    """One signed immutable OCI release selected through a fixed profile."""

    schema_: Literal[SUCCESSOR_RELEASE_TARGET_SCHEMA] = Field(alias="schema")
    artifact_type: Literal["oci"] = "oci"
    release_bundle_url: Annotated[str, Field(min_length=1, max_length=2_048)]
    release_bundle_sha256: Hex32
    release_bundle_size_bytes: Annotated[int, Field(gt=0, le=MAX_SUPERVISOR_RELEASE_BUNDLE_BYTES)]
    release_manifest_sha256: Hex32
    release_authority_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    release_authority_signature_scheme: Literal["sr25519", "ed25519"]
    oci_repository: Annotated[str, Field(min_length=1, max_length=512)]
    oci_manifest_sha256: Hex32
    target_platform: Literal["linux/amd64", "linux/arm64"]
    umi_git_revision: Annotated[str, Field(min_length=40, max_length=40)]
    umi_source_tree_sha256: Hex32
    entrypoint_profile: SuccessorEntrypointProfile
    state_schema_minimum: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    state_schema_maximum: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    replay_release_identity: CompetitionReleaseIdentity

    @model_validator(mode="after")
    def validate_release(self) -> Self:
        account_id32(self.release_authority_hotkey)
        if _OCI_REPOSITORY_RE.fullmatch(self.oci_repository) is None:
            raise ValueError("successor OCI repository is not canonical")
        if _GIT_REVISION_RE.fullmatch(self.umi_git_revision) is None:
            raise ValueError("successor UMI revision must be lowercase hexadecimal")
        if self.state_schema_maximum < self.state_schema_minimum:
            raise ValueError("successor release state schema range is inverted")
        if not (
            self.state_schema_minimum <= SUCCESSOR_STATE_SCHEMA_VERSION <= self.state_schema_maximum
        ):
            raise ValueError("successor release does not support the v4 state schema")
        _release_url_origin(self.release_bundle_url)
        identity = self.replay_release_identity
        if (
            identity.umi_revision != self.umi_git_revision
            or identity.release_manifest_sha256 != self.release_manifest_sha256
            or identity.release_bundle_sha256 != self.release_bundle_sha256
            or identity.target_triple != _TARGET_TRIPLE[self.target_platform]
        ):
            raise ValueError("successor release and replay identity disagree")
        return self


class SuccessorReplayPackageTarget(StrictProtocolModel):
    """Exact sealed replay package and the limits under which it must be read."""

    schema_: Literal[SUCCESSOR_REPLAY_PACKAGE_TARGET_SCHEMA] = Field(alias="schema")
    artifact_type: Literal["sealed_competition_replay_package"] = (
        "sealed_competition_replay_package"
    )
    profile: Literal["competition_publication_replay_no_weight/1"] = (
        "competition_publication_replay_no_weight/1"
    )
    package_sha256: Hex32
    manifest_sha256: Hex32
    policy_sha256: Hex32
    policy_valid_from_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    policy_valid_through_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    round_sha256: Hex32
    round_sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    cutoff_publication_sha256: Hex32
    cutoff_certificate_sha256: Hex32
    settlement_publication_sha256: Hex32
    settlement_certificate_sha256: Hex32
    settlement_sha256: Hex32
    projection_sha256: Hex32
    promotion_head_sha256: Hex32
    release_identity_sha256: Hex32
    limits: CompetitionPackageLimits

    @model_validator(mode="after")
    def validate_policy_interval(self) -> Self:
        if self.policy_valid_through_block <= self.policy_valid_from_block:
            raise ValueError("successor package policy interval is empty")
        return self


class SuccessorChainAuthorizationTarget(StrictProtocolModel):
    """Exact separate signed authorization required by the weight profile."""

    schema_: Literal[SUCCESSOR_CHAIN_AUTHORIZATION_TARGET_SCHEMA] = Field(alias="schema")
    artifact_type: Literal["canonical_json"] = "canonical_json"
    profile: Literal["umi-signed-competition-weight-authorization/1"] = (
        "umi-signed-competition-weight-authorization/1"
    )
    authorization_id: Hex32
    signed_authorization_sha256: Hex32
    authorization_size_bytes: Annotated[
        int, Field(gt=0, le=MAX_SUCCESSOR_CHAIN_AUTHORIZATION_BYTES)
    ]
    policy_sha256: Hex32
    package_sha256: Hex32
    settlement_sha256: Hex32
    projection_sha256: Hex32
    release_identity_sha256: Hex32
    predecessor_directive_sha256: Hex32
    valid_from_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    valid_through_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    required_recovery_profile: Literal["stopped_bootstrap_recovery/1"]

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if self.valid_through_block < self.valid_from_block:
            raise ValueError("successor chain authorization interval is inverted")
        return self


class SuccessorSupervisorOperatorConsent(StrictProtocolModel):
    """Root-owned local consent that narrows signed successor authority.

    The host loader must establish file ownership, mode, and exact bytes. This
    record contains no authority keys and cannot replace the v3 trust policy.
    """

    schema_: Literal[SUCCESSOR_SUPERVISOR_OPERATOR_CONSENT_SCHEMA] = Field(alias="schema")
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

    @field_validator("validator_hotkey")
    @classmethod
    def validate_validator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_consent(self) -> Self:
        expected = [mode for mode in _MODE_ORDER if mode in self.allowed_modes]
        if self.allowed_modes != expected:
            raise ValueError("successor consent modes must be unique and canonically ordered")
        if self.valid_through_block < self.authorized_at_finalized_block:
            raise ValueError("successor operator consent interval is inverted")
        if self.authorized_at_finalized_block < self.predecessor_accepted_at_finalized_block:
            raise ValueError("successor consent predates its predecessor observation")
        return self


class SuccessorSupervisorDirective(StrictProtocolModel):
    """One v4 hold, wallet-free replay, or chain-capable weight decision."""

    schema_: Literal[SUCCESSOR_SUPERVISOR_DIRECTIVE_SCHEMA] = Field(alias="schema")
    channel_id: Hex32
    sequence: Annotated[int, Field(ge=2, le=MAX_JSON_SAFE_INTEGER)]
    predecessor_version: SuccessorPredecessorVersion
    previous_directive_sha256: Hex32
    issued_at_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    valid_from_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    valid_through_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    minimum_activation_headroom_blocks: Annotated[
        int,
        Field(
            ge=MIN_SUCCESSOR_ACTIVATION_HEADROOM_BLOCKS,
            le=MAX_SUCCESSOR_ACTIVATION_HEADROOM_BLOCKS,
        ),
    ]
    network: Literal["finney"] = "finney"
    netuid: Literal[78] = 78
    mechanism_id: Literal[0] = 0
    mode: SuccessorSupervisorMode
    validator_scope: SuccessorValidatorScope
    validator_hotkeys: Annotated[list[str], Field(max_length=MAX_SUPERVISOR_VALIDATORS)]
    policy_sha256: Hex32 | None
    required_host_manifest_sha256: Hex32
    required_recovery_profile: Literal["stopped_bootstrap_recovery/1"]
    chain: SuccessorSupervisorChainTarget
    capabilities: SuccessorWorkerCapabilities | None
    release: SuccessorSupervisorReleaseTarget | None
    replay_package: SuccessorReplayPackageTarget | None
    chain_authorization: SuccessorChainAuthorizationTarget | None

    @model_validator(mode="after")
    def validate_directive(self) -> Self:
        if not self.issued_at_block <= self.valid_from_block <= self.valid_through_block:
            raise ValueError("successor directive block interval is invalid")
        accounts = [account_id32(item) for item in self.validator_hotkeys]
        if accounts != sorted(accounts) or len(set(accounts)) != len(accounts):
            raise ValueError("successor validator hotkeys must be unique and sorted")
        if self.validator_scope == "explicit_hotkeys" and not accounts:
            raise ValueError("an explicit successor scope requires validator hotkeys")
        if self.validator_scope == "any_permitted_sn78" and accounts:
            raise ValueError("a common successor scope cannot name validator hotkeys")
        if (
            self.chain.network != self.network
            or self.chain.netuid != self.netuid
            or self.chain.mechanism_id != self.mechanism_id
        ):
            raise ValueError("successor directive and chain target disagree")
        if self.mode == "hold":
            if any(
                item is not None
                for item in (
                    self.policy_sha256,
                    self.capabilities,
                    self.release,
                    self.replay_package,
                    self.chain_authorization,
                )
            ):
                raise ValueError("a successor hold cannot carry worker authority")
            return self
        if any(
            item is None
            for item in (
                self.policy_sha256,
                self.capabilities,
                self.release,
                self.replay_package,
            )
        ):
            raise ValueError("a successor worker directive is incomplete")
        capabilities = self.capabilities
        release = self.release
        package = self.replay_package
        assert capabilities is not None and release is not None and package is not None
        expected = {
            "competition_replay": (
                "umi-competition-replay-worker/1",
                "none",
                "none",
                False,
            ),
            "competition_weights": (
                "umi-competition-weight-worker/1",
                "configured_validator_hotkey_read_only",
                "finney_clients",
                True,
            ),
        }[self.mode]
        observed = (
            release.entrypoint_profile,
            capabilities.wallet_access,
            capabilities.network_access,
            capabilities.chain_submission,
        )
        if observed != expected:
            raise ValueError("successor mode, release, and capabilities disagree")
        if (
            self.policy_sha256 != package.policy_sha256
            or package.release_identity_sha256
            != competition_release_identity_digest(release.replay_release_identity)
            or self.valid_from_block < package.policy_valid_from_block
            or self.valid_through_block > package.policy_valid_through_block
        ):
            raise ValueError("successor directive and replay package disagree")
        authorization = self.chain_authorization
        if self.mode == "competition_replay":
            if authorization is not None:
                raise ValueError("wallet-free replay cannot carry chain authorization")
        elif authorization is None:
            raise ValueError("competition weights require separate chain authorization")
        elif (
            authorization.policy_sha256 != package.policy_sha256
            or authorization.package_sha256 != package.package_sha256
            or authorization.settlement_sha256 != package.settlement_sha256
            or authorization.projection_sha256 != package.projection_sha256
            or authorization.release_identity_sha256 != package.release_identity_sha256
            or authorization.predecessor_directive_sha256 != self.previous_directive_sha256
            or authorization.required_recovery_profile != self.required_recovery_profile
            or authorization.valid_from_block > self.valid_from_block
            or authorization.valid_through_block < self.valid_through_block
        ):
            raise ValueError("chain authorization target and successor directive disagree")
        return self


class SignedSuccessorSupervisorDirective(StrictProtocolModel):
    """A v4 directive with a canonical threshold-signature set."""

    schema_: Literal[SUCCESSOR_SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA] = Field(alias="schema")
    directive: SuccessorSupervisorDirective
    directive_sha256: Hex32
    directive_digest: Hex32
    signatures: Annotated[
        list[SupervisorDirectiveSignature],
        Field(min_length=1, max_length=MAX_SUPERVISOR_AUTHORITIES),
    ]

    @model_validator(mode="after")
    def validate_binding_and_order(self) -> Self:
        if not hmac.compare_digest(
            self.directive_sha256,
            successor_supervisor_directive_sha256(self.directive),
        ):
            raise ValueError("signed successor directive has the wrong content hash")
        if not hmac.compare_digest(
            self.directive_digest,
            successor_supervisor_directive_digest(self.directive).hex(),
        ):
            raise ValueError("signed successor directive has the wrong signing digest")
        accounts = [account_id32(item.hotkey) for item in self.signatures]
        if accounts != sorted(accounts) or len(set(accounts)) != len(accounts):
            raise ValueError("successor signatures must be unique and sorted")
        return self


class SuccessorSupervisorDirectivePage(StrictProtocolModel):
    """One cursor-bound page whose first v4 item names the cursor version."""

    schema_: Literal[SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA] = Field(alias="schema")
    after_version: SuccessorPredecessorVersion
    after_sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    after_directive_sha256: Hex32
    directives: Annotated[
        list[SignedSuccessorSupervisorDirective],
        Field(max_length=MAX_SUPERVISOR_DIRECTIVES_PER_PAGE),
    ]
    more: bool
    head: SignedSuccessorSupervisorDirective

    @model_validator(mode="after")
    def validate_cursor_chain_and_head(self) -> Self:
        if not self.directives:
            if self.more or self.after_version != 4:
                raise ValueError("an empty successor page requires a v4 caught-up cursor")
            if self.head.directive.sequence != self.after_sequence or not hmac.compare_digest(
                self.head.directive_sha256,
                self.after_directive_sha256,
            ):
                raise ValueError("empty successor page head does not match its cursor")
            return self
        predecessor = self.after_directive_sha256
        version: SuccessorPredecessorVersion = self.after_version
        sequence = self.after_sequence + 1
        for signed in self.directives:
            directive = signed.directive
            if (
                directive.sequence != sequence
                or directive.predecessor_version != version
                or not hmac.compare_digest(directive.previous_directive_sha256, predecessor)
            ):
                raise ValueError("successor directive page is not predecessor-contiguous")
            predecessor = signed.directive_sha256
            version = 4
            sequence += 1
        if self.head != self.directives[-1]:
            raise ValueError("successor page head must equal its final directive")
        return self


class SuccessorSupervisorDirectiveState(StrictProtocolModel):
    """Durable v4 high-water with the exact v3 transition anchor."""

    schema_: Literal[SUCCESSOR_SUPERVISOR_DIRECTIVE_STATE_SCHEMA] = Field(alias="schema")
    channel_id: Hex32
    transition_v3_sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    transition_v3_directive_sha256: Hex32
    transition_v3_signed_directive_sha256: Hex32
    transition_v3_accepted_at_finalized_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    operator_consent_sha256: Hex32
    source_config_sha256: Hex32
    accepted_sequence: Annotated[int, Field(ge=2, le=MAX_JSON_SAFE_INTEGER)]
    accepted_directive_sha256: Hex32
    accepted_at_finalized_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    accepted_mode: SuccessorSupervisorMode
    accepted_oci_manifest_sha256: Hex32 | None
    accepted_package_sha256: Hex32 | None
    accepted_chain_authorization_sha256: Hex32 | None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.accepted_sequence <= self.transition_v3_sequence:
            raise ValueError("successor state does not advance its v3 transition anchor")
        if self.accepted_at_finalized_block < self.transition_v3_accepted_at_finalized_block:
            raise ValueError("successor state rolls back finalized high-water")
        values = (
            self.accepted_oci_manifest_sha256,
            self.accepted_package_sha256,
            self.accepted_chain_authorization_sha256,
        )
        if self.accepted_mode == "hold":
            if any(value is not None for value in values):
                raise ValueError("successor hold state carries worker authority")
        elif self.accepted_mode == "competition_replay":
            if values[0] is None or values[1] is None or values[2] is not None:
                raise ValueError("successor replay state has invalid authority bindings")
        elif any(value is None for value in values):
            raise ValueError("successor weight state lacks an authority binding")
        return self


def successor_supervisor_directive_digest(directive: SuccessorSupervisorDirective) -> bytes:
    """Return the v4 domain-separated digest signed by old trusted authorities."""

    if not isinstance(directive, SuccessorSupervisorDirective):
        raise TypeError("directive must be a SuccessorSupervisorDirective")
    return hashlib.sha256(
        SUCCESSOR_SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN + canonical_json_bytes(directive)
    ).digest()


def successor_supervisor_directive_sha256(directive: SuccessorSupervisorDirective) -> str:
    """Return the v4 content hash used by the cross-version predecessor chain."""

    if not isinstance(directive, SuccessorSupervisorDirective):
        raise TypeError("directive must be a SuccessorSupervisorDirective")
    return hashlib.sha256(canonical_json_bytes(directive)).hexdigest()


def successor_operator_consent_sha256(
    consent: SuccessorSupervisorOperatorConsent,
) -> str:
    """Bind the exact local operator-consent record for durable audit state."""

    consent = _canonical(SuccessorSupervisorOperatorConsent, consent)
    return hashlib.sha256(
        SUCCESSOR_OPERATOR_CONSENT_DOMAIN + canonical_json_bytes(consent)
    ).hexdigest()


def successor_source_config_sha256(config: ValidatorSupervisorConfig) -> str:
    """Return the exact canonical v3 configuration hash named by local consent."""

    if not isinstance(config, ValidatorSupervisorConfig):
        raise TypeError("config must be a ValidatorSupervisorConfig")
    return hashlib.sha256(canonical_json_bytes(config)).hexdigest()


def parse_canonical_signed_successor_supervisor_directive(
    payload: bytes,
    *,
    maximum_bytes: int = MAX_SUCCESSOR_DOCUMENT_BYTES,
) -> SignedSuccessorSupervisorDirective:
    value = _parse_canonical_json(payload, maximum_bytes=maximum_bytes, label="successor_directive")
    try:
        signed = SignedSuccessorSupervisorDirective.model_validate(value)
    except Exception as error:
        raise ValidatorSupervisorError("successor_directive_schema_invalid") from error
    if canonical_json_bytes(signed) != payload:
        raise ValidatorSupervisorError("successor_directive_noncanonical")
    return signed


def parse_canonical_successor_supervisor_directive_page(
    payload: bytes,
    *,
    maximum_bytes: int = MAX_SUCCESSOR_DOCUMENT_BYTES,
) -> SuccessorSupervisorDirectivePage:
    value = _parse_canonical_json(payload, maximum_bytes=maximum_bytes, label="successor_page")
    try:
        page = SuccessorSupervisorDirectivePage.model_validate(value)
    except Exception as error:
        raise ValidatorSupervisorError("successor_page_schema_invalid") from error
    if canonical_json_bytes(page) != payload:
        raise ValidatorSupervisorError("successor_page_noncanonical")
    return page


def parse_canonical_successor_operator_consent(
    payload: bytes,
    *,
    maximum_bytes: int = MAX_SUCCESSOR_DOCUMENT_BYTES,
) -> SuccessorSupervisorOperatorConsent:
    value = _parse_canonical_json(payload, maximum_bytes=maximum_bytes, label="successor_consent")
    try:
        consent = SuccessorSupervisorOperatorConsent.model_validate(value)
    except Exception as error:
        raise ValidatorSupervisorError("successor_consent_schema_invalid") from error
    if canonical_json_bytes(consent) != payload:
        raise ValidatorSupervisorError("successor_consent_noncanonical")
    return consent


def parse_canonical_successor_supervisor_state(
    payload: bytes,
    *,
    maximum_bytes: int = MAX_SUCCESSOR_DOCUMENT_BYTES,
) -> SuccessorSupervisorDirectiveState:
    value = _parse_canonical_json(payload, maximum_bytes=maximum_bytes, label="successor_state")
    try:
        state = SuccessorSupervisorDirectiveState.model_validate(value)
    except Exception as error:
        raise ValidatorSupervisorError("successor_state_schema_invalid") from error
    if canonical_json_bytes(state) != payload:
        raise ValidatorSupervisorError("successor_state_noncanonical")
    return state


def verify_signed_successor_supervisor_directive(
    signed: SignedSuccessorSupervisorDirective,
    *,
    config: ValidatorSupervisorConfig,
    operator_consent: SuccessorSupervisorOperatorConsent,
    finalized_block: int,
) -> str:
    """Verify v4 authority and local consent without advancing high-water state.

    This verifier may inspect a directive before ``valid_from_block``. Only the
    advance functions below may create an accepted state, and they reject a
    future directive.
    """

    return _verify_signed_successor_supervisor_directive(
        signed,
        config=config,
        operator_consent=operator_consent,
        finalized_block=finalized_block,
        require_unexpired=True,
    )


def verify_signed_successor_supervisor_directive_history(
    signed: SignedSuccessorSupervisorDirective,
    *,
    config: ValidatorSupervisorConfig,
    operator_consent: SuccessorSupervisorOperatorConsent,
    finalized_block: int,
) -> str:
    """Verify an expired v4 predecessor for catch-up without activating it."""

    return _verify_signed_successor_supervisor_directive(
        signed,
        config=config,
        operator_consent=operator_consent,
        finalized_block=finalized_block,
        require_unexpired=False,
    )


def _verify_signed_successor_supervisor_directive(
    signed: SignedSuccessorSupervisorDirective,
    *,
    config: ValidatorSupervisorConfig,
    operator_consent: SuccessorSupervisorOperatorConsent,
    finalized_block: int,
    require_unexpired: bool,
) -> str:
    if not isinstance(signed, SignedSuccessorSupervisorDirective):
        raise TypeError("signed must be a SignedSuccessorSupervisorDirective")
    if not isinstance(config, ValidatorSupervisorConfig):
        raise TypeError("config must be a ValidatorSupervisorConfig")
    if not isinstance(operator_consent, SuccessorSupervisorOperatorConsent):
        raise TypeError("operator_consent must be a SuccessorSupervisorOperatorConsent")
    _validate_finalized_block(finalized_block)
    directive = signed.directive
    consent = operator_consent
    config_sha256 = successor_source_config_sha256(config)
    if consent.source_config_sha256 != config_sha256:
        raise ValidatorSupervisorError("successor_source_config_mismatch")
    if directive.channel_id != config.channel_id or consent.channel_id != config.channel_id:
        raise ValidatorSupervisorError("successor_channel_mismatch")
    if account_id32(consent.validator_hotkey) != account_id32(config.validator_hotkey):
        raise ValidatorSupervisorError("successor_consent_validator_mismatch")
    if consent.target_platform != config.target_platform:
        raise ValidatorSupervisorError("successor_consent_platform_mismatch")
    if directive.required_host_manifest_sha256 != consent.approved_host_manifest_sha256:
        raise ValidatorSupervisorError("successor_host_manifest_not_consented")
    if directive.required_recovery_profile != consent.required_recovery_profile:
        raise ValidatorSupervisorError("successor_recovery_profile_not_consented")
    if directive.mode != "hold" and directive.mode not in consent.allowed_modes:
        raise ValidatorSupervisorError("successor_mode_not_consented")
    if finalized_block < directive.issued_at_block:
        raise ValidatorSupervisorError("successor_directive_issued_in_future")
    if finalized_block < consent.authorized_at_finalized_block:
        raise ValidatorSupervisorError("successor_operator_consent_not_active")
    if finalized_block > consent.valid_through_block:
        raise ValidatorSupervisorError("successor_operator_consent_expired")
    if (
        directive.valid_from_block < consent.authorized_at_finalized_block
        or directive.valid_through_block > consent.valid_through_block
    ):
        raise ValidatorSupervisorError("successor_directive_outside_operator_consent")
    if require_unexpired and finalized_block > directive.valid_through_block:
        raise ValidatorSupervisorError("successor_directive_expired")
    validator_account = account_id32(config.validator_hotkey)
    directive_accounts = [account_id32(item) for item in directive.validator_hotkeys]
    if directive.validator_scope == "explicit_hotkeys":
        if validator_account not in directive_accounts:
            raise ValidatorSupervisorError("successor_validator_not_authorized")
    elif directive.validator_scope != "any_permitted_sn78":  # pragma: no cover
        raise ValidatorSupervisorError("successor_validator_scope_invalid")
    release = directive.release
    if release is not None:
        if release.oci_repository not in config.allowed_oci_repositories:
            raise ValidatorSupervisorError("successor_oci_repository_not_allowed")
        if _release_url_origin(release.release_bundle_url) not in config.release_origins:
            raise ValidatorSupervisorError("successor_release_origin_not_allowed")
        if release.target_platform != config.target_platform:
            raise ValidatorSupervisorError("successor_release_platform_mismatch")
        authorities = {account_id32(item.hotkey): item for item in config.trusted_authorities}
        authority = authorities.get(account_id32(release.release_authority_hotkey))
        if authority is None:
            raise ValidatorSupervisorError("successor_release_authority_untrusted")
        if authority.signature_scheme != release.release_authority_signature_scheme:
            raise ValidatorSupervisorError("successor_release_authority_scheme_mismatch")
    authority_by_account = {account_id32(item.hotkey): item for item in config.trusted_authorities}
    verified = 0
    digest = successor_supervisor_directive_digest(directive)
    for signature in signed.signatures:
        authority = authority_by_account.get(account_id32(signature.hotkey))
        if authority is None:
            raise ValidatorSupervisorError("successor_directive_signer_untrusted")
        if signature.signature_scheme != authority.signature_scheme:
            raise ValidatorSupervisorError("successor_directive_signature_scheme_mismatch")
        if not verify_response_signature(
            digest,
            hotkey_ss58=signature.hotkey,
            scheme=signature.signature_scheme,
            signature=signature.signature,
        ):
            raise ValidatorSupervisorError("successor_directive_signature_invalid")
        verified += 1
    if verified < config.signature_threshold:
        raise ValidatorSupervisorError("successor_directive_signature_threshold_not_met")
    return signed.directive_sha256


def advance_successor_supervisor_directive_state(
    signed: SignedSuccessorSupervisorDirective,
    *,
    config: ValidatorSupervisorConfig,
    operator_consent: SuccessorSupervisorOperatorConsent,
    finalized_block: int,
    prior_state: SupervisorDirectiveState | SuccessorSupervisorDirectiveState,
    prior_v3_signed_bytes: bytes | None = None,
) -> SuccessorSupervisorDirectiveState:
    """Advance one active v4 directive without resetting the v3 high-water mark."""

    digest = verify_signed_successor_supervisor_directive(
        signed,
        config=config,
        operator_consent=operator_consent,
        finalized_block=finalized_block,
    )
    return _advance_successor_supervisor_directive_state(
        signed,
        digest=digest,
        config=config,
        operator_consent=operator_consent,
        finalized_block=finalized_block,
        prior_state=prior_state,
        prior_v3_signed_bytes=prior_v3_signed_bytes,
        require_activation_headroom=True,
    )


def advance_successor_supervisor_directive_history_state(
    signed: SignedSuccessorSupervisorDirective,
    *,
    config: ValidatorSupervisorConfig,
    operator_consent: SuccessorSupervisorOperatorConsent,
    finalized_block: int,
    prior_state: SupervisorDirectiveState | SuccessorSupervisorDirectiveState,
    prior_v3_signed_bytes: bytes | None = None,
) -> SuccessorSupervisorDirectiveState:
    """Advance an active-or-expired v4 catch-up item without executing it."""

    digest = verify_signed_successor_supervisor_directive_history(
        signed,
        config=config,
        operator_consent=operator_consent,
        finalized_block=finalized_block,
    )
    return _advance_successor_supervisor_directive_state(
        signed,
        digest=digest,
        config=config,
        operator_consent=operator_consent,
        finalized_block=finalized_block,
        prior_state=prior_state,
        prior_v3_signed_bytes=prior_v3_signed_bytes,
        require_activation_headroom=False,
    )


def _advance_successor_supervisor_directive_state(
    signed: SignedSuccessorSupervisorDirective,
    *,
    digest: str,
    config: ValidatorSupervisorConfig,
    operator_consent: SuccessorSupervisorOperatorConsent,
    finalized_block: int,
    prior_state: SupervisorDirectiveState | SuccessorSupervisorDirectiveState,
    prior_v3_signed_bytes: bytes | None,
    require_activation_headroom: bool,
) -> SuccessorSupervisorDirectiveState:
    directive = signed.directive
    consent = operator_consent
    if finalized_block < directive.valid_from_block:
        raise ValidatorSupervisorError("successor_directive_not_yet_active")
    if require_activation_headroom and (
        directive.valid_through_block - finalized_block
        < directive.minimum_activation_headroom_blocks
    ):
        raise ValidatorSupervisorError("successor_activation_headroom_insufficient")
    consent_sha256 = successor_operator_consent_sha256(consent)
    config_sha256 = successor_source_config_sha256(config)
    if isinstance(prior_state, SupervisorDirectiveState):
        if prior_v3_signed_bytes is None:
            raise ValidatorSupervisorError("successor_v3_signed_predecessor_required")
        prior_signed = parse_canonical_signed_supervisor_directive(prior_v3_signed_bytes)
        verified_prior = advance_supervisor_directive_history_state(
            prior_signed,
            config=config,
            finalized_block=finalized_block,
            prior_state=prior_state,
        )
        if verified_prior != prior_state:
            raise ValidatorSupervisorError("successor_v3_state_binding_mismatch")
        predecessor_signed_sha256 = hashlib.sha256(prior_v3_signed_bytes).hexdigest()
        if (
            directive.predecessor_version != 3
            or directive.sequence != prior_state.accepted_sequence + 1
            or not hmac.compare_digest(
                directive.previous_directive_sha256,
                prior_state.accepted_directive_sha256,
            )
            or consent.predecessor_sequence != prior_state.accepted_sequence
            or consent.predecessor_directive_sha256 != prior_state.accepted_directive_sha256
            or consent.predecessor_signed_directive_sha256 != predecessor_signed_sha256
            or consent.predecessor_accepted_at_finalized_block
            != prior_state.accepted_at_finalized_block
        ):
            raise ValidatorSupervisorError("successor_v3_transition_binding_mismatch")
        transition = (
            prior_state.accepted_sequence,
            prior_state.accepted_directive_sha256,
            predecessor_signed_sha256,
            prior_state.accepted_at_finalized_block,
        )
    elif isinstance(prior_state, SuccessorSupervisorDirectiveState):
        if prior_v3_signed_bytes is not None:
            raise ValidatorSupervisorError("successor_v3_predecessor_unexpected")
        if finalized_block < prior_state.accepted_at_finalized_block:
            raise ValidatorSupervisorError("successor_finalized_block_rollback")
        if (
            prior_state.channel_id != config.channel_id
            or prior_state.operator_consent_sha256 != consent_sha256
            or prior_state.source_config_sha256 != config_sha256
            or prior_state.transition_v3_sequence != consent.predecessor_sequence
            or prior_state.transition_v3_directive_sha256 != consent.predecessor_directive_sha256
            or prior_state.transition_v3_signed_directive_sha256
            != consent.predecessor_signed_directive_sha256
            or prior_state.transition_v3_accepted_at_finalized_block
            != consent.predecessor_accepted_at_finalized_block
        ):
            raise ValidatorSupervisorError("successor_state_transition_binding_mismatch")
        if directive.sequence == prior_state.accepted_sequence:
            if not hmac.compare_digest(digest, prior_state.accepted_directive_sha256):
                raise ValidatorSupervisorError("successor_directive_sequence_equivocation")
            if prior_state != _state_for(
                signed,
                finalized_block=prior_state.accepted_at_finalized_block,
                consent=consent,
                transition=(
                    prior_state.transition_v3_sequence,
                    prior_state.transition_v3_directive_sha256,
                    prior_state.transition_v3_signed_directive_sha256,
                    prior_state.transition_v3_accepted_at_finalized_block,
                ),
                source_config_sha256=config_sha256,
            ):
                raise ValidatorSupervisorError("successor_state_execution_binding_mismatch")
            return prior_state
        if directive.sequence < prior_state.accepted_sequence:
            raise ValidatorSupervisorError("successor_directive_sequence_rollback")
        if directive.sequence != prior_state.accepted_sequence + 1:
            raise ValidatorSupervisorError("successor_directive_sequence_gap")
        if directive.predecessor_version != 4 or not hmac.compare_digest(
            directive.previous_directive_sha256,
            prior_state.accepted_directive_sha256,
        ):
            raise ValidatorSupervisorError("successor_directive_predecessor_mismatch")
        transition = (
            prior_state.transition_v3_sequence,
            prior_state.transition_v3_directive_sha256,
            prior_state.transition_v3_signed_directive_sha256,
            prior_state.transition_v3_accepted_at_finalized_block,
        )
    else:
        raise TypeError("prior_state must be a v3 or v4 supervisor directive state")
    return _state_for(
        signed,
        finalized_block=finalized_block,
        consent=consent,
        transition=transition,
        source_config_sha256=config_sha256,
    )


def _state_for(
    signed: SignedSuccessorSupervisorDirective,
    *,
    finalized_block: int,
    consent: SuccessorSupervisorOperatorConsent,
    transition: tuple[int, str, str, int],
    source_config_sha256: str,
) -> SuccessorSupervisorDirectiveState:
    directive = signed.directive
    release = directive.release
    package = directive.replay_package
    authorization = directive.chain_authorization
    return SuccessorSupervisorDirectiveState(
        schema=SUCCESSOR_SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
        channel_id=directive.channel_id,
        transition_v3_sequence=transition[0],
        transition_v3_directive_sha256=transition[1],
        transition_v3_signed_directive_sha256=transition[2],
        transition_v3_accepted_at_finalized_block=transition[3],
        operator_consent_sha256=successor_operator_consent_sha256(consent),
        source_config_sha256=source_config_sha256,
        accepted_sequence=directive.sequence,
        accepted_directive_sha256=signed.directive_sha256,
        accepted_at_finalized_block=finalized_block,
        accepted_mode=directive.mode,
        accepted_oci_manifest_sha256=(None if release is None else release.oci_manifest_sha256),
        accepted_package_sha256=None if package is None else package.package_sha256,
        accepted_chain_authorization_sha256=(
            None if authorization is None else authorization.signed_authorization_sha256
        ),
    )


def load_bound_successor_replay_package(
    package_path: Path,
    *,
    directive: SuccessorSupervisorDirective,
    observed_release: CompetitionReleaseIdentity,
) -> VerifiedCompetitionPackage:
    """Load the exact package selected by one already-authenticated directive."""

    target = directive.replay_package
    release = directive.release
    if directive.mode == "hold" or target is None or release is None:
        raise ValidatorSupervisorError("successor_replay_package_not_selected")
    if observed_release != release.replay_release_identity:
        raise ValidatorSupervisorError("successor_observed_release_mismatch")
    package = load_competition_package(
        package_path,
        expected_package_sha256=target.package_sha256,
        expected_policy_sha256=target.policy_sha256,
        observed_release=observed_release,
        limits=target.limits,
    )
    manifest = package.manifest
    expected = (
        target.manifest_sha256,
        target.policy_sha256,
        target.policy_valid_from_block,
        target.policy_valid_through_block,
        target.round_sha256,
        target.round_sequence,
        target.cutoff_publication_sha256,
        target.cutoff_certificate_sha256,
        target.settlement_publication_sha256,
        target.settlement_certificate_sha256,
        target.settlement_sha256,
        target.projection_sha256,
        target.promotion_head_sha256,
        target.release_identity_sha256,
    )
    observed = (
        package.manifest_sha256,
        manifest.policy_sha256,
        package.policy.valid_from_block,
        package.policy.valid_through_block,
        manifest.round_sha256,
        manifest.round_sequence,
        manifest.cutoff_publication_sha256,
        manifest.cutoff_certificate_sha256,
        manifest.settlement_publication_sha256,
        manifest.settlement_certificate_sha256,
        manifest.settlement_sha256,
        manifest.projection_sha256,
        manifest.promotion_head_sha256,
        manifest.release_identity_sha256,
    )
    if observed != expected:
        raise ValidatorSupervisorError("successor_replay_package_binding_mismatch")
    return package


def verify_bound_successor_chain_authorization(
    authorization_bytes: bytes,
    *,
    directive: SuccessorSupervisorDirective,
    config: ValidatorSupervisorConfig,
    package: VerifiedCompetitionPackage,
) -> CompetitionWeightAuthorizationBody:
    """Verify exact separate chain authority for an authenticated weight directive."""

    if not isinstance(authorization_bytes, bytes):
        raise TypeError("authorization_bytes must be bytes")
    if not isinstance(directive, SuccessorSupervisorDirective):
        raise TypeError("directive must be a SuccessorSupervisorDirective")
    if not isinstance(config, ValidatorSupervisorConfig):
        raise TypeError("config must be a ValidatorSupervisorConfig")
    if not isinstance(package, VerifiedCompetitionPackage):
        raise TypeError("package must be a VerifiedCompetitionPackage")
    target = directive.chain_authorization
    if directive.mode != "competition_weights" or target is None:
        raise ValidatorSupervisorError("successor_chain_authorization_not_selected")
    if len(authorization_bytes) != target.authorization_size_bytes:
        raise ValidatorSupervisorError("successor_chain_authorization_size_mismatch")
    value = _parse_canonical_json(
        authorization_bytes,
        maximum_bytes=MAX_SUCCESSOR_CHAIN_AUTHORIZATION_BYTES,
        label="successor_chain_authorization",
    )
    try:
        signed = SignedCompetitionWeightAuthorization.model_validate(value)
    except Exception as error:
        raise ValidatorSupervisorError("successor_chain_authorization_schema_invalid") from error
    if canonical_json_bytes(signed) != authorization_bytes:
        raise ValidatorSupervisorError("successor_chain_authorization_noncanonical")
    if not hmac.compare_digest(
        hashlib.sha256(authorization_bytes).hexdigest(),
        target.signed_authorization_sha256,
    ):
        raise ValidatorSupervisorError("successor_chain_authorization_digest_mismatch")
    body = signed.authorization
    observed = (
        body.authorization_id,
        body.policy_sha256,
        body.package_sha256,
        body.settlement_sha256,
        body.projection_sha256,
        body.release_identity_sha256,
        body.predecessor_directive_sha256,
        body.valid_from_block,
        body.valid_through_block,
        body.required_recovery_profile,
    )
    expected = (
        target.authorization_id,
        target.policy_sha256,
        target.package_sha256,
        target.settlement_sha256,
        target.projection_sha256,
        target.release_identity_sha256,
        target.predecessor_directive_sha256,
        target.valid_from_block,
        target.valid_through_block,
        target.required_recovery_profile,
    )
    if observed != expected:
        raise ValidatorSupervisorError("successor_chain_authorization_binding_mismatch")
    if (
        body.network != directive.network
        or body.netuid != directive.netuid
        or body.mechanism_id != directive.mechanism_id
        or body.chain_pin != directive.chain.chain_pin
    ):
        raise ValidatorSupervisorError("successor_chain_authorization_chain_mismatch")
    authority_by_account = {account_id32(item.hotkey): item for item in config.trusted_authorities}
    authority = authority_by_account.get(account_id32(signed.signature.hotkey))
    if authority is None:
        raise ValidatorSupervisorError("successor_chain_authorization_signer_untrusted")
    if signed.signature.scheme != authority.signature_scheme:
        raise ValidatorSupervisorError("successor_chain_authorization_signature_scheme_mismatch")
    try:
        verified = verify_competition_weight_authorization(
            signed,
            trusted_authority_hotkeys=tuple(item.hotkey for item in config.trusted_authorities),
            package=package,
        )
    except (TypeError, ValueError) as error:
        raise ValidatorSupervisorError("successor_chain_authorization_invalid") from error
    if verified != body:  # pragma: no cover - verifier returns its exact body
        raise ValidatorSupervisorError("successor_chain_authorization_result_mismatch")
    return body


def _canonical(model_type: type[_ModelT], value: _ModelT) -> _ModelT:
    return model_type.model_validate_json(canonical_json_bytes(value), strict=True)


def _validate_finalized_block(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("finalized_block must be an integer")
    if not 1 <= value <= MAX_JSON_SAFE_INTEGER:
        raise ValueError("finalized_block is outside the canonical range")


def _parse_canonical_json(payload: bytes, *, maximum_bytes: int, label: str) -> Any:
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be a positive integer")
    if not payload or len(payload) > maximum_bytes:
        raise ValidatorSupervisorError(f"{label}_size_invalid")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        reason = (
            f"{label}_duplicate_key" if "duplicate key" in str(error) else f"{label}_json_invalid"
        )
        raise ValidatorSupervisorError(reason) from error
    try:
        if canonical_json_bytes(value) != payload:
            raise ValidatorSupervisorError(f"{label}_noncanonical")
    except ValidatorSupervisorError:
        raise
    except Exception as error:
        raise ValidatorSupervisorError(f"{label}_noncanonical") from error
    return value


def _release_url_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("successor release bundle URL is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or parsed.query
        or parsed.fragment
        or parsed.netloc != parsed.hostname
        or parsed.hostname != parsed.hostname.lower()
    ):
        raise ValueError("successor release bundle URL is not canonical HTTPS")
    return f"https://{parsed.hostname}"


__all__ = [
    "MAX_SUCCESSOR_ACTIVATION_HEADROOM_BLOCKS",
    "MAX_SUCCESSOR_CHAIN_AUTHORIZATION_BYTES",
    "MAX_SUCCESSOR_DOCUMENT_BYTES",
    "MIN_SUCCESSOR_ACTIVATION_HEADROOM_BLOCKS",
    "SUCCESSOR_CHAIN_AUTHORIZATION_TARGET_SCHEMA",
    "SUCCESSOR_CHAIN_TARGET_SCHEMA",
    "SUCCESSOR_RELEASE_TARGET_SCHEMA",
    "SUCCESSOR_REPLAY_PACKAGE_TARGET_SCHEMA",
    "SUCCESSOR_STATE_SCHEMA_VERSION",
    "SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA",
    "SUCCESSOR_SUPERVISOR_DIRECTIVE_SCHEMA",
    "SUCCESSOR_SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN",
    "SUCCESSOR_SUPERVISOR_DIRECTIVE_STATE_SCHEMA",
    "SUCCESSOR_SUPERVISOR_OPERATOR_CONSENT_SCHEMA",
    "SUCCESSOR_SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA",
    "SUCCESSOR_WORKER_CAPABILITIES_SCHEMA",
    "SignedSuccessorSupervisorDirective",
    "SuccessorChainAuthorizationTarget",
    "SuccessorEntrypointProfile",
    "SuccessorPredecessorVersion",
    "SuccessorReplayPackageTarget",
    "SuccessorSupervisorChainTarget",
    "SuccessorSupervisorDirective",
    "SuccessorSupervisorDirectivePage",
    "SuccessorSupervisorDirectiveState",
    "SuccessorSupervisorMode",
    "SuccessorSupervisorOperatorConsent",
    "SuccessorSupervisorReleaseTarget",
    "SuccessorValidatorScope",
    "SuccessorWorkerCapabilities",
    "advance_successor_supervisor_directive_history_state",
    "advance_successor_supervisor_directive_state",
    "load_bound_successor_replay_package",
    "parse_canonical_signed_successor_supervisor_directive",
    "parse_canonical_successor_operator_consent",
    "parse_canonical_successor_supervisor_directive_page",
    "parse_canonical_successor_supervisor_state",
    "successor_operator_consent_sha256",
    "successor_source_config_sha256",
    "successor_supervisor_directive_digest",
    "successor_supervisor_directive_sha256",
    "verify_bound_successor_chain_authorization",
    "verify_signed_successor_supervisor_directive",
    "verify_signed_successor_supervisor_directive_history",
]
