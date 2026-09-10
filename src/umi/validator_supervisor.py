"""Authenticated control records for the install-once UMI validator supervisor.

This module is deliberately limited to schemas, signature verification, and
monotonic local state. It performs no network, wallet, subprocess, container, or
chain operation. Runtime code must complete its own finalized-chain and host
checks before acting on an accepted directive.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .crypto import verify_response_signature
from .encoding import account_id32
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

SUPERVISOR_CONFIG_SCHEMA = "umi-validator-supervisor-config/1"
SUPERVISOR_TRUST_POLICY_SCHEMA = "umi-validator-supervisor-trust-policy/1"
SUPERVISOR_DIRECTIVE_SCHEMA = "umi-validator-supervisor-directive/3"
SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA = "umi-validator-supervisor-signed-directive/3"
SUPERVISOR_DIRECTIVE_PAGE_SCHEMA = "umi-validator-supervisor-directive-page/3"
SUPERVISOR_DIRECTIVE_STATE_SCHEMA = "umi-validator-supervisor-directive-state/3"

SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN = b"umi-validator-supervisor-directive-v3\0"
MAX_SUPERVISOR_DOCUMENT_BYTES = 1024 * 1024
MAX_SUPERVISOR_AUTHORITIES = 16
MAX_SUPERVISOR_VALIDATORS = 65_536
MAX_SUPERVISOR_DIRECTIVES_PER_PAGE = 64
MAX_SUPERVISOR_RELEASE_BUNDLE_BYTES = 1024 * 1024 * 1024
MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_JSON_SAFE_INTEGER = (1 << 53) - 1
COMMON_SUPERVISOR_AUTHORITY_HOTKEY = "5GsPXiSyzpK3rRoeAmjT4F5Cqa1RmP1CyBvNpwNDsDejyNZ4"
COMMON_SUPERVISOR_RELEASE_ORIGIN = "https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev"
COMMON_SUPERVISOR_CHANNELS = {
    "linux/amd64": "a3ca19a108fe7d1a8e53a2db76f480ebe237b7942595f23135d6e11889ed40c0",
    "linux/arm64": "85ea6ef2c7e4f24d9d0eefa367425119b509e8604ce1675443efcbacc7bb4461",
}

SupervisorMode = Literal[
    "hold",
    "inactive_shadow",
    "bootstrap_service_weights",
    "translation_weights",
]
SupervisorEntrypointProfile = Literal[
    "umi-live-shadow-validator/1",
    "umi-bootstrap-weight-validator/2",
    "umi-simple-bootstrap-validator/1",
    "umi-translation-validator/1",
]
SupervisorValidatorScope = Literal["explicit_hotkeys", "any_permitted_sn78"]

_GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_OCI_REPOSITORY_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?"
    r"(?::[1-9][0-9]{0,4})?"
    r"/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class ValidatorSupervisorError(RuntimeError):
    """Stable, non-sensitive rejection from supervisor control-plane work."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class SupervisorAuthority(StrictProtocolModel):
    """One out-of-band trusted directive signer."""

    hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    signature_scheme: Literal["sr25519", "ed25519"]

    @field_validator("hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value


class SupervisorTrustPolicy(StrictProtocolModel):
    """Pinned local trust root for one independent directive channel."""

    schema_: Literal[SUPERVISOR_TRUST_POLICY_SCHEMA] = Field(alias="schema")
    channel_id: Hex32
    signature_threshold: Annotated[int, Field(ge=1, le=MAX_SUPERVISOR_AUTHORITIES)]
    authorities: Annotated[
        list[SupervisorAuthority],
        Field(min_length=1, max_length=MAX_SUPERVISOR_AUTHORITIES),
    ]

    @model_validator(mode="after")
    def validate_authorities(self) -> Self:
        accounts = [account_id32(item.hotkey) for item in self.authorities]
        if accounts != sorted(accounts) or len(set(accounts)) != len(accounts):
            raise ValueError("supervisor authorities must be unique and AccountId32-sorted")
        if self.signature_threshold > len(self.authorities):
            raise ValueError("supervisor signature threshold exceeds authority count")
        return self


class SupervisorWalletBinding(StrictProtocolModel):
    """Private local binding to one dedicated validator hotkey wallet tree."""

    path: Annotated[str, Field(min_length=1, max_length=4_096)]
    name: Annotated[str, Field(min_length=1, max_length=128)]
    hotkey: Annotated[str, Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        path = Path(self.path)
        if not path.is_absolute() or path != Path(os.path.normpath(path)):
            raise ValueError("supervisor wallet path must be absolute and normalized")
        if _NAME_RE.fullmatch(self.name) is None or _NAME_RE.fullmatch(self.hotkey) is None:
            raise ValueError("supervisor wallet names must be canonical")
        return self


class ValidatorSupervisorConfig(StrictProtocolModel):
    """Static local consent and trust configuration installed by an operator."""

    schema_: Literal[SUPERVISOR_CONFIG_SCHEMA] = Field(alias="schema")
    network: Literal["finney"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    channel_id: Hex32
    signature_threshold: Annotated[int, Field(ge=1, le=MAX_SUPERVISOR_AUTHORITIES)]
    trusted_authorities: Annotated[
        list[SupervisorAuthority],
        Field(min_length=1, max_length=MAX_SUPERVISOR_AUTHORITIES),
    ]
    allowed_oci_repositories: Annotated[list[str], Field(min_length=1, max_length=16)]
    release_origins: Annotated[list[str], Field(min_length=1, max_length=16)]
    target_platform: Literal["linux/amd64", "linux/arm64"]
    state_schema_version: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    directive_url: Annotated[str, Field(min_length=1, max_length=2_048)]
    poll_seconds: Annotated[int, Field(ge=30, le=3_600)]
    container_runtime: Literal["/usr/bin/podman"]
    state_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    worker_state_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    release_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    operator_input_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    finality_verifier_binary: Annotated[str, Field(min_length=1, max_length=4_096)]
    finality_verifier_sha256: Hex32
    finality_chain_spec_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    worker_cpu_millis: Annotated[int, Field(ge=100, le=256_000)]
    worker_memory_bytes: Annotated[int, Field(ge=268_435_456, le=274_877_906_944)]
    worker_pids_limit: Annotated[int, Field(ge=16, le=4_096)]
    worker_uid: Annotated[int, Field(ge=1, le=2_147_483_647)]
    worker_gid: Annotated[int, Field(ge=1, le=2_147_483_647)]
    wallet: SupervisorWalletBinding
    allowed_modes: Annotated[list[SupervisorMode], Field(min_length=1, max_length=4)]

    @field_validator("validator_hotkey")
    @classmethod
    def validate_validator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_config(self) -> Self:
        policy = self.trust_policy()
        if policy.channel_id != self.channel_id:
            raise ValueError("supervisor channel IDs disagree")
        repositories = self.allowed_oci_repositories
        if (
            repositories != sorted(repositories)
            or len(set(repositories)) != len(repositories)
            or any(_OCI_REPOSITORY_RE.fullmatch(item) is None for item in repositories)
        ):
            raise ValueError("allowed OCI repositories must be unique, canonical, and sorted")
        if (
            self.release_origins != sorted(self.release_origins)
            or len(set(self.release_origins)) != len(self.release_origins)
            or any(_canonical_https_origin(item) != item for item in self.release_origins)
        ):
            raise ValueError("release origins must be unique, canonical, and sorted")
        try:
            parsed_url = urlsplit(self.directive_url)
            parsed_port = parsed_url.port
        except ValueError as error:
            raise ValueError("supervisor directive URL is invalid") from error
        if (
            parsed_url.scheme != "https"
            or parsed_url.hostname is None
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_port not in {None, 443}
            or not parsed_url.path.startswith("/")
            or parsed_url.path == "/"
            or parsed_url.query
            or parsed_url.fragment
            or (parsed_port is None and parsed_url.netloc != parsed_url.hostname)
        ):
            raise ValueError("supervisor directive URL must be a credential-free HTTPS URL")
        local_roots: list[tuple[str, str]] = [
            ("state", self.state_root),
            ("worker state", self.worker_state_root),
            ("release", self.release_root),
            ("operator input", self.operator_input_root),
            ("wallet", self.wallet.path),
        ]
        for label, value in local_roots:
            path = Path(value)
            if not path.is_absolute() or path != Path(os.path.normpath(path)):
                raise ValueError(f"supervisor {label} root must be absolute and normalized")
        paths = [Path(value) for _, value in local_roots]
        for index, path in enumerate(paths):
            others = paths[:index] + paths[index + 1 :]
            if any(
                path == other or path in other.parents or other in path.parents for other in others
            ):
                raise ValueError("supervisor local roots must be pairwise disjoint")
        for label, value in (
            ("finality verifier", self.finality_verifier_binary),
            ("finality chain spec", self.finality_chain_spec_path),
        ):
            path = Path(value)
            if not path.is_absolute() or path != Path(os.path.normpath(path)):
                raise ValueError(f"supervisor {label} path must be absolute and normalized")
        expected_order = [
            "hold",
            "inactive_shadow",
            "bootstrap_service_weights",
            "translation_weights",
        ]
        if self.allowed_modes != [item for item in expected_order if item in self.allowed_modes]:
            raise ValueError("supervisor allowed modes must be unique and canonically ordered")
        return self

    def trust_policy(self) -> SupervisorTrustPolicy:
        return SupervisorTrustPolicy(
            schema=SUPERVISOR_TRUST_POLICY_SCHEMA,
            channel_id=self.channel_id,
            signature_threshold=self.signature_threshold,
            authorities=self.trusted_authorities,
        )


class SupervisorReleaseTarget(StrictProtocolModel):
    """One immutable OCI worker selected by a signed directive."""

    artifact_type: Literal["oci"]
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
    entrypoint_profile: SupervisorEntrypointProfile
    state_schema_minimum: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    state_schema_maximum: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]

    @model_validator(mode="after")
    def validate_release(self) -> Self:
        account_id32(self.release_authority_hotkey)
        if _OCI_REPOSITORY_RE.fullmatch(self.oci_repository) is None:
            raise ValueError("OCI repository is not canonical or contains a tag/digest")
        if _GIT_REVISION_RE.fullmatch(self.umi_git_revision) is None:
            raise ValueError("UMI Git revision must be lowercase 40-character hexadecimal")
        if self.state_schema_maximum < self.state_schema_minimum:
            raise ValueError("release state schema range is inverted")
        _release_url_origin(self.release_bundle_url)
        return self


class SupervisorOperatorInputTarget(StrictProtocolModel):
    """One immutable canonical input bundle selected by a signed directive."""

    artifact_type: Literal["canonical_json"]
    profile: Literal[
        "umi-bootstrap-direct-inputs/2",
        "umi-simple-bootstrap-common-inputs/1",
    ]
    bundle_url: Annotated[str, Field(min_length=1, max_length=2_048)]
    bundle_sha256: Hex32
    bundle_size_bytes: Annotated[int, Field(gt=0, le=MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES)]

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        _release_url_origin(self.bundle_url)
        return self


class SupervisorDirective(StrictProtocolModel):
    """One ordered, expiring hold or worker-activation decision."""

    schema_: Literal[SUPERVISOR_DIRECTIVE_SCHEMA] = Field(alias="schema")
    channel_id: Hex32
    sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    previous_directive_sha256: Hex32 | None
    issued_at_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    valid_from_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    valid_through_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    network: Literal["finney"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    mode: SupervisorMode
    validator_scope: SupervisorValidatorScope = "explicit_hotkeys"
    validator_hotkeys: Annotated[list[str], Field(max_length=MAX_SUPERVISOR_VALIDATORS)]
    policy_sha256: Hex32 | None
    release: SupervisorReleaseTarget | None
    operator_inputs: SupervisorOperatorInputTarget | None = None

    @model_validator(mode="after")
    def validate_directive(self) -> Self:
        if not self.issued_at_block <= self.valid_from_block <= self.valid_through_block:
            raise ValueError("supervisor directive block interval is invalid")
        if (self.sequence == 1) != (self.previous_directive_sha256 is None):
            raise ValueError("only the first supervisor directive may omit its predecessor")
        accounts = [account_id32(item) for item in self.validator_hotkeys]
        if accounts != sorted(accounts) or len(set(accounts)) != len(accounts):
            raise ValueError("supervisor validator hotkeys must be unique and AccountId32-sorted")
        if self.validator_scope == "explicit_hotkeys" and not accounts:
            raise ValueError("an explicit validator scope requires at least one hotkey")
        if self.validator_scope == "any_permitted_sn78" and accounts:
            raise ValueError("a common validator scope cannot contain validator hotkeys")
        if self.mode == "hold":
            if (
                self.policy_sha256 is not None
                or self.release is not None
                or self.operator_inputs is not None
            ):
                raise ValueError("a hold directive cannot name a policy, release, or input bundle")
        else:
            if self.policy_sha256 is None or self.release is None:
                raise ValueError("a worker directive requires a policy and release")
            expected_profile = {
                "inactive_shadow": "umi-live-shadow-validator/1",
                "bootstrap_service_weights": {
                    "explicit_hotkeys": "umi-bootstrap-weight-validator/2",
                    "any_permitted_sn78": "umi-simple-bootstrap-validator/1",
                }[self.validator_scope],
                "translation_weights": "umi-translation-validator/1",
            }[self.mode]
            if self.release.entrypoint_profile != expected_profile:
                raise ValueError("worker mode and entrypoint profile disagree")
            if self.mode == "bootstrap_service_weights":
                if self.operator_inputs is None:
                    raise ValueError("bootstrap mode requires an immutable operator-input bundle")
                expected_input_profile = {
                    "explicit_hotkeys": "umi-bootstrap-direct-inputs/2",
                    "any_permitted_sn78": "umi-simple-bootstrap-common-inputs/1",
                }[self.validator_scope]
                if self.operator_inputs.profile != expected_input_profile:
                    raise ValueError("validator scope and bootstrap input profile disagree")
            elif self.operator_inputs is not None:
                raise ValueError("only bootstrap mode may name an operator-input bundle")
        return self


class SupervisorDirectiveSignature(StrictProtocolModel):
    """One authority signature over the directive digest."""

    hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]

    @field_validator("hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value


class SignedSupervisorDirective(StrictProtocolModel):
    """A directive plus its canonical threshold-signature set."""

    schema_: Literal[SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA] = Field(alias="schema")
    directive: SupervisorDirective
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
            supervisor_directive_sha256(self.directive),
        ):
            raise ValueError("signed supervisor directive has the wrong content hash")
        if not hmac.compare_digest(
            self.directive_digest,
            supervisor_directive_digest(self.directive).hex(),
        ):
            raise ValueError("signed supervisor directive has the wrong signing digest")
        accounts = [account_id32(item.hotkey) for item in self.signatures]
        if accounts != sorted(accounts) or len(set(accounts)) != len(accounts):
            raise ValueError("supervisor signatures must be unique and AccountId32-sorted")
        return self


class SupervisorDirectivePage(StrictProtocolModel):
    """One cursor-bound, canonical page of a signed directive chain.

    ``head`` authenticates the server's latest claimed directive even when the
    caller is already caught up and ``directives`` is empty.  An untrusted
    server can withhold a newer directive, but it cannot extend the signed
    head's lease.
    """

    schema_: Literal[SUPERVISOR_DIRECTIVE_PAGE_SCHEMA] = Field(alias="schema")
    after_sequence: Annotated[int, Field(ge=0, le=MAX_JSON_SAFE_INTEGER)]
    after_directive_sha256: Hex32 | None
    directives: Annotated[
        list[SignedSupervisorDirective],
        Field(max_length=MAX_SUPERVISOR_DIRECTIVES_PER_PAGE),
    ]
    more: bool
    head: SignedSupervisorDirective

    @model_validator(mode="after")
    def validate_cursor_chain_and_head(self) -> Self:
        if (self.after_sequence == 0) != (self.after_directive_sha256 is None):
            raise ValueError("directive-page initial cursor is invalid")
        if self.more and not self.directives:
            raise ValueError("a continued directive page cannot be empty")
        if not self.directives:
            if self.after_sequence == 0:
                raise ValueError("the initial directive page cannot be empty")
            if self.head.directive.sequence != self.after_sequence or not hmac.compare_digest(
                self.head.directive_sha256,
                self.after_directive_sha256 or "",
            ):
                raise ValueError("empty directive-page head does not match its cursor")
            return self

        predecessor = self.after_directive_sha256
        expected_sequence = self.after_sequence + 1
        for signed in self.directives:
            directive = signed.directive
            if directive.sequence != expected_sequence:
                raise ValueError("directive page is not sequence-contiguous")
            if not hmac.compare_digest(
                directive.previous_directive_sha256 or "",
                predecessor or "",
            ):
                raise ValueError("directive page is not predecessor-contiguous")
            expected_sequence += 1
            predecessor = signed.directive_sha256
        if self.head != self.directives[-1]:
            raise ValueError("directive-page head must equal its final directive")
        return self


class SupervisorDirectiveState(StrictProtocolModel):
    """Durable high-water mark for one accepted directive channel."""

    schema_: Literal[SUPERVISOR_DIRECTIVE_STATE_SCHEMA] = Field(alias="schema")
    channel_id: Hex32
    accepted_sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    accepted_directive_sha256: Hex32
    accepted_at_finalized_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    accepted_mode: SupervisorMode
    accepted_oci_manifest_sha256: Hex32 | None
    accepted_operator_input_sha256: Hex32 | None = None

    @model_validator(mode="after")
    def validate_worker_fence(self) -> Self:
        if (self.accepted_mode == "hold") != (self.accepted_oci_manifest_sha256 is None):
            raise ValueError("accepted OCI manifest digest must be null exactly when mode is hold")
        if (self.accepted_mode == "bootstrap_service_weights") != (
            self.accepted_operator_input_sha256 is not None
        ):
            raise ValueError(
                "accepted operator-input digest must exist exactly when mode is bootstrap"
            )
        return self


def supervisor_directive_digest(directive: SupervisorDirective) -> bytes:
    """Return the domain-separated SHA-256 digest signed by authorities."""

    if not isinstance(directive, SupervisorDirective):
        raise TypeError("directive must be a SupervisorDirective")
    return hashlib.sha256(
        SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN + canonical_json_bytes(directive)
    ).digest()


def supervisor_directive_sha256(directive: SupervisorDirective) -> str:
    """Return the content hash used by the directive predecessor chain."""

    if not isinstance(directive, SupervisorDirective):
        raise TypeError("directive must be a SupervisorDirective")
    return hashlib.sha256(canonical_json_bytes(directive)).hexdigest()


def parse_canonical_signed_supervisor_directive(
    payload: bytes,
    *,
    maximum_bytes: int = MAX_SUPERVISOR_DOCUMENT_BYTES,
) -> SignedSupervisorDirective:
    """Parse exact canonical JSON while rejecting duplicate object keys."""

    value = _parse_canonical_json(payload, maximum_bytes=maximum_bytes, label="directive")
    try:
        signed = SignedSupervisorDirective.model_validate(value)
    except Exception as error:
        raise ValidatorSupervisorError("directive_schema_invalid") from error
    if canonical_json_bytes(signed) != payload:
        raise ValidatorSupervisorError("directive_noncanonical")
    return signed


def parse_canonical_supervisor_directive_page(
    payload: bytes,
    *,
    maximum_bytes: int = MAX_SUPERVISOR_DOCUMENT_BYTES,
) -> SupervisorDirectivePage:
    """Parse one exact canonical cursor-bound directive page."""

    value = _parse_canonical_json(payload, maximum_bytes=maximum_bytes, label="directive_page")
    try:
        page = SupervisorDirectivePage.model_validate(value)
    except Exception as error:
        raise ValidatorSupervisorError("directive_page_schema_invalid") from error
    if canonical_json_bytes(page) != payload:
        raise ValidatorSupervisorError("directive_page_noncanonical")
    return page


def parse_canonical_validator_supervisor_config(
    payload: bytes,
    *,
    maximum_bytes: int = MAX_SUPERVISOR_DOCUMENT_BYTES,
) -> ValidatorSupervisorConfig:
    """Parse one exact canonical local supervisor configuration."""

    value = _parse_canonical_json(payload, maximum_bytes=maximum_bytes, label="config")
    try:
        config = ValidatorSupervisorConfig.model_validate(value)
    except Exception as error:
        raise ValidatorSupervisorError("config_schema_invalid") from error
    if canonical_json_bytes(config) != payload:
        raise ValidatorSupervisorError("config_noncanonical")
    return config


def load_validator_supervisor_config(path: str | Path) -> ValidatorSupervisorConfig:
    """Load a canonical root- or service-owned, non-writable configuration."""

    target = Path(path)
    if not target.is_absolute() or target != Path(os.path.normpath(target)):
        raise ValidatorSupervisorError("config_path_invalid")
    try:
        descriptor = os.open(target, _read_flags())
    except OSError as error:
        raise ValidatorSupervisorError("config_read_failed") from error
    try:
        metadata = os.fstat(descriptor)
        allowed_modes = {0o400, 0o440, 0o600, 0o640}
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in allowed_modes
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ValidatorSupervisorError("config_file_unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(MAX_SUPERVISOR_DOCUMENT_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    config = parse_canonical_validator_supervisor_config(payload)
    for root in (
        config.state_root,
        config.worker_state_root,
        config.release_root,
        config.operator_input_root,
    ):
        _require_private_directory(Path(root))
    return config


def verify_signed_supervisor_directive(
    signed: SignedSupervisorDirective,
    *,
    config: ValidatorSupervisorConfig,
    finalized_block: int,
) -> str:
    """Verify threshold authority and static local consent for one directive."""

    return _verify_signed_supervisor_directive(
        signed,
        config=config,
        finalized_block=finalized_block,
        require_unexpired=True,
    )


def _verify_signed_supervisor_directive(
    signed: SignedSupervisorDirective,
    *,
    config: ValidatorSupervisorConfig,
    finalized_block: int,
    require_unexpired: bool,
) -> str:
    """Shared verifier; only catch-up history may waive lease freshness."""

    if not isinstance(signed, SignedSupervisorDirective):
        raise TypeError("signed must be a SignedSupervisorDirective")
    if not isinstance(config, ValidatorSupervisorConfig):
        raise TypeError("config must be a ValidatorSupervisorConfig")
    if isinstance(finalized_block, bool) or not isinstance(finalized_block, int):
        raise TypeError("finalized_block must be an integer")
    try:
        validator_account = account_id32(config.validator_hotkey)
    except Exception as error:
        raise ValidatorSupervisorError("validator_hotkey_invalid") from error
    directive = signed.directive
    trust_policy = config.trust_policy()
    if directive.channel_id != trust_policy.channel_id:
        raise ValidatorSupervisorError("directive_channel_mismatch")
    directive_validators = [account_id32(item) for item in directive.validator_hotkeys]
    if directive.validator_scope == "explicit_hotkeys":
        if directive_validators != [validator_account]:
            raise ValidatorSupervisorError("directive_validator_not_authorized")
    elif directive.validator_scope != "any_permitted_sn78":  # pragma: no cover
        raise ValidatorSupervisorError("directive_validator_scope_invalid")
    if directive.mode not in set(config.allowed_modes):
        raise ValidatorSupervisorError("directive_mode_not_locally_allowed")
    if finalized_block < directive.issued_at_block:
        raise ValidatorSupervisorError("directive_issued_in_future")
    if require_unexpired and finalized_block > directive.valid_through_block:
        raise ValidatorSupervisorError("directive_expired")
    if directive.release is not None:
        if directive.release.oci_repository not in config.allowed_oci_repositories:
            raise ValidatorSupervisorError("directive_oci_repository_not_allowed")
        if _release_url_origin(directive.release.release_bundle_url) not in config.release_origins:
            raise ValidatorSupervisorError("directive_release_origin_not_allowed")
        authority_by_account = {
            account_id32(item.hotkey): item for item in config.trusted_authorities
        }
        release_authority = authority_by_account.get(
            account_id32(directive.release.release_authority_hotkey)
        )
        if release_authority is None:
            raise ValidatorSupervisorError("directive_release_authority_untrusted")
        if (
            release_authority.signature_scheme
            != directive.release.release_authority_signature_scheme
        ):
            raise ValidatorSupervisorError("directive_release_authority_scheme_mismatch")
        if directive.release.target_platform != config.target_platform:
            raise ValidatorSupervisorError("directive_target_platform_mismatch")
        if not (
            directive.release.state_schema_minimum
            <= config.state_schema_version
            <= directive.release.state_schema_maximum
        ):
            raise ValidatorSupervisorError("directive_state_schema_incompatible")
    if (
        directive.operator_inputs is not None
        and _release_url_origin(directive.operator_inputs.bundle_url) not in config.release_origins
    ):
        raise ValidatorSupervisorError("directive_operator_input_origin_not_allowed")

    authority_by_account = {account_id32(item.hotkey): item for item in trust_policy.authorities}
    verified = 0
    digest = supervisor_directive_digest(directive)
    for signature in signed.signatures:
        authority = authority_by_account.get(account_id32(signature.hotkey))
        if authority is None:
            raise ValidatorSupervisorError("directive_signer_untrusted")
        if signature.signature_scheme != authority.signature_scheme:
            raise ValidatorSupervisorError("directive_signature_scheme_mismatch")
        if not verify_response_signature(
            digest,
            hotkey_ss58=signature.hotkey,
            scheme=signature.signature_scheme,
            signature=signature.signature,
        ):
            raise ValidatorSupervisorError("directive_signature_invalid")
        verified += 1
    if verified < trust_policy.signature_threshold:
        raise ValidatorSupervisorError("directive_signature_threshold_not_met")
    return signed.directive_sha256


def verify_signed_supervisor_directive_history(
    signed: SignedSupervisorDirective,
    *,
    config: ValidatorSupervisorConfig,
    finalized_block: int,
) -> str:
    """Verify a signed historical directive without requiring an unexpired lease.

    This is only for advancing the durable catch-up high-water mark.  It keeps
    every signature and local-consent check and still rejects directives whose
    claimed issue block is in the future.  A caller MUST NOT execute or preflight
    a directive accepted through this function.
    """

    return _verify_signed_supervisor_directive(
        signed,
        config=config,
        finalized_block=finalized_block,
        require_unexpired=False,
    )


def advance_supervisor_directive_state(
    signed: SignedSupervisorDirective,
    *,
    config: ValidatorSupervisorConfig,
    finalized_block: int,
    prior_state: SupervisorDirectiveState | None,
) -> SupervisorDirectiveState:
    """Verify and advance one exact monotonic directive chain."""

    digest = verify_signed_supervisor_directive(
        signed,
        config=config,
        finalized_block=finalized_block,
    )
    return _advance_supervisor_directive_state(
        signed,
        digest=digest,
        config=config,
        finalized_block=finalized_block,
        prior_state=prior_state,
    )


def advance_supervisor_directive_history_state(
    signed: SignedSupervisorDirective,
    *,
    config: ValidatorSupervisorConfig,
    finalized_block: int,
    prior_state: SupervisorDirectiveState | None,
) -> SupervisorDirectiveState:
    """Advance catch-up history, including expired entries, without executing it."""

    digest = verify_signed_supervisor_directive_history(
        signed,
        config=config,
        finalized_block=finalized_block,
    )
    return _advance_supervisor_directive_state(
        signed,
        digest=digest,
        config=config,
        finalized_block=finalized_block,
        prior_state=prior_state,
    )


def _advance_supervisor_directive_state(
    signed: SignedSupervisorDirective,
    *,
    digest: str,
    config: ValidatorSupervisorConfig,
    finalized_block: int,
    prior_state: SupervisorDirectiveState | None,
) -> SupervisorDirectiveState:
    """Apply already-verified content to the monotonic state transition."""

    trust_policy = config.trust_policy()
    directive = signed.directive
    if prior_state is None:
        if directive.sequence != 1 or directive.previous_directive_sha256 is not None:
            raise ValidatorSupervisorError("directive_initial_sequence_invalid")
    else:
        if prior_state.channel_id != trust_policy.channel_id:
            raise ValidatorSupervisorError("directive_state_channel_mismatch")
        if finalized_block < prior_state.accepted_at_finalized_block:
            raise ValidatorSupervisorError("directive_finalized_block_rollback")
        if directive.sequence == prior_state.accepted_sequence:
            if not hmac.compare_digest(digest, prior_state.accepted_directive_sha256):
                raise ValidatorSupervisorError("directive_sequence_equivocation")
            expected_manifest = (
                None if directive.release is None else directive.release.oci_manifest_sha256
            )
            expected_operator_input = (
                None
                if directive.operator_inputs is None
                else directive.operator_inputs.bundle_sha256
            )
            if (
                prior_state.accepted_mode != directive.mode
                or prior_state.accepted_oci_manifest_sha256 != expected_manifest
                or prior_state.accepted_operator_input_sha256 != expected_operator_input
            ):
                raise ValidatorSupervisorError("directive_state_execution_binding_mismatch")
            return prior_state
        if directive.sequence < prior_state.accepted_sequence:
            raise ValidatorSupervisorError("directive_sequence_rollback")
        if directive.sequence != prior_state.accepted_sequence + 1:
            raise ValidatorSupervisorError("directive_sequence_gap")
        if not hmac.compare_digest(
            directive.previous_directive_sha256 or "",
            prior_state.accepted_directive_sha256,
        ):
            raise ValidatorSupervisorError("directive_predecessor_mismatch")
    return SupervisorDirectiveState(
        schema=SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
        channel_id=trust_policy.channel_id,
        accepted_sequence=directive.sequence,
        accepted_directive_sha256=digest,
        accepted_at_finalized_block=finalized_block,
        accepted_mode=directive.mode,
        accepted_oci_manifest_sha256=(
            None if directive.release is None else directive.release.oci_manifest_sha256
        ),
        accepted_operator_input_sha256=(
            None if directive.operator_inputs is None else directive.operator_inputs.bundle_sha256
        ),
    )


def parse_canonical_supervisor_directive_state(
    payload: bytes,
    *,
    trust_policy: SupervisorTrustPolicy,
    maximum_bytes: int = MAX_SUPERVISOR_DOCUMENT_BYTES,
) -> SupervisorDirectiveState:
    """Parse and bind one canonical persisted high-water record."""

    value = _parse_canonical_json(payload, maximum_bytes=maximum_bytes, label="state")
    try:
        state = SupervisorDirectiveState.model_validate(value)
    except Exception as error:
        raise ValidatorSupervisorError("directive_state_schema_invalid") from error
    if canonical_json_bytes(state) != payload:
        raise ValidatorSupervisorError("directive_state_noncanonical")
    if state.channel_id != trust_policy.channel_id:
        raise ValidatorSupervisorError("directive_state_channel_mismatch")
    return state


def load_supervisor_directive_state(
    path: str | Path,
    *,
    trust_policy: SupervisorTrustPolicy,
) -> SupervisorDirectiveState | None:
    """Load a private regular state file; absence means no directive was accepted."""

    target = _validated_state_path(path)
    try:
        descriptor = os.open(target, _read_flags())
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ValidatorSupervisorError("directive_state_read_failed") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValidatorSupervisorError("directive_state_file_unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(MAX_SUPERVISOR_DOCUMENT_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return parse_canonical_supervisor_directive_state(payload, trust_policy=trust_policy)


def store_supervisor_directive_state(
    path: str | Path,
    state: SupervisorDirectiveState,
    *,
    trust_policy: SupervisorTrustPolicy,
    expected_prior: SupervisorDirectiveState | None,
) -> None:
    """Atomically store a verified advance without overwriting unexpected state."""

    if not isinstance(state, SupervisorDirectiveState):
        raise TypeError("state must be a SupervisorDirectiveState")
    try:
        state = SupervisorDirectiveState.model_validate(
            state.model_dump(mode="python", by_alias=True)
        )
    except Exception as error:
        raise ValidatorSupervisorError("directive_state_schema_invalid") from error
    if state.channel_id != trust_policy.channel_id:
        raise ValidatorSupervisorError("directive_state_channel_mismatch")
    target = _validated_state_path(path)
    parent = target.parent
    _require_private_directory(parent)
    lock_path = parent / f".{target.name}.lock"
    with _open_state_lock(lock_path) as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        observed = load_supervisor_directive_state(target, trust_policy=trust_policy)
        if observed != expected_prior:
            raise ValidatorSupervisorError("directive_state_compare_failed")
        if observed is None:
            if state.accepted_sequence != 1:
                raise ValidatorSupervisorError("directive_state_initial_sequence_invalid")
        elif state.accepted_sequence == observed.accepted_sequence:
            if state != observed:
                reason = (
                    "directive_state_equivocation"
                    if state.accepted_directive_sha256 != observed.accepted_directive_sha256
                    else "directive_state_same_sequence_changed"
                )
                raise ValidatorSupervisorError(reason)
        else:
            if state.accepted_sequence < observed.accepted_sequence:
                raise ValidatorSupervisorError("directive_state_rollback")
            if state.accepted_sequence != observed.accepted_sequence + 1:
                raise ValidatorSupervisorError("directive_state_sequence_gap")
            if state.accepted_at_finalized_block < observed.accepted_at_finalized_block:
                raise ValidatorSupervisorError("directive_state_finalized_block_rollback")
        payload = canonical_json_bytes(state)
        temporary = parent / f".{target.name}.{os.getpid()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            directory_descriptor = os.open(parent, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError as error:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()
            raise ValidatorSupervisorError("directive_state_write_failed") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)


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

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite number")

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
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


def _read_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _require_private_directory(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            component_metadata = current.lstat()
        except OSError as error:
            raise ValidatorSupervisorError("directive_state_directory_missing") from error
        if stat.S_ISLNK(component_metadata.st_mode):
            raise ValidatorSupervisorError("directive_state_directory_unsafe")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValidatorSupervisorError("directive_state_directory_missing") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValidatorSupervisorError("directive_state_directory_unsafe")


def _validated_state_path(path: str | Path) -> Path:
    target = Path(path)
    if not target.is_absolute() or target != Path(os.path.normpath(target)):
        raise ValidatorSupervisorError("directive_state_path_invalid")
    return target


def _canonical_https_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("release origin is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.netloc != parsed.hostname
        or parsed.hostname != parsed.hostname.lower()
    ):
        raise ValueError("release origin must be canonical HTTPS without a port or path")
    return f"https://{parsed.hostname}"


def _release_url_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("release bundle URL is invalid") from error
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
        raise ValueError("release bundle URL must be canonical credential-free HTTPS")
    return f"https://{parsed.hostname}"


def _open_state_lock(path: Path) -> Any:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ValidatorSupervisorError("directive_state_lock_failed") from error
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise ValidatorSupervisorError("directive_state_lock_unsafe")
    return os.fdopen(descriptor, "r+")


__all__ = [
    "COMMON_SUPERVISOR_AUTHORITY_HOTKEY",
    "COMMON_SUPERVISOR_CHANNELS",
    "COMMON_SUPERVISOR_RELEASE_ORIGIN",
    "MAX_SUPERVISOR_DIRECTIVES_PER_PAGE",
    "MAX_SUPERVISOR_DOCUMENT_BYTES",
    "MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES",
    "MAX_SUPERVISOR_RELEASE_BUNDLE_BYTES",
    "SUPERVISOR_CONFIG_SCHEMA",
    "SUPERVISOR_DIRECTIVE_PAGE_SCHEMA",
    "SUPERVISOR_DIRECTIVE_SCHEMA",
    "SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN",
    "SUPERVISOR_DIRECTIVE_STATE_SCHEMA",
    "SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA",
    "SUPERVISOR_TRUST_POLICY_SCHEMA",
    "SignedSupervisorDirective",
    "SupervisorAuthority",
    "SupervisorDirective",
    "SupervisorDirectivePage",
    "SupervisorDirectiveSignature",
    "SupervisorDirectiveState",
    "SupervisorEntrypointProfile",
    "SupervisorMode",
    "SupervisorOperatorInputTarget",
    "SupervisorReleaseTarget",
    "SupervisorTrustPolicy",
    "SupervisorValidatorScope",
    "SupervisorWalletBinding",
    "ValidatorSupervisorConfig",
    "ValidatorSupervisorError",
    "advance_supervisor_directive_history_state",
    "advance_supervisor_directive_state",
    "load_supervisor_directive_state",
    "load_validator_supervisor_config",
    "parse_canonical_signed_supervisor_directive",
    "parse_canonical_supervisor_directive_page",
    "parse_canonical_supervisor_directive_state",
    "parse_canonical_validator_supervisor_config",
    "store_supervisor_directive_state",
    "supervisor_directive_digest",
    "supervisor_directive_sha256",
    "verify_signed_supervisor_directive_history",
]
