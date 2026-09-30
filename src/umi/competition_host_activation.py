"""Durable host-installation seal and opaque successor worker capabilities.

The installation receipt records a transition that was checked while the
legacy supervisor was stopped.  It grants no chain authority.  After restart,
only the fixed read-only activation mount can recreate worker inputs.  Weight
activation additionally requires a fresh process-local owned chain observation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal, TypeVar

from pydantic import Field, field_validator, model_serializer, model_validator
from typing_extensions import Self

from .competition_evidence_config import EvidenceStorageConfig
from .competition_evidence_migration_models import EvidenceMigrationSeal
from .competition_history_compatibility import (
    original_consent_digest,
    validate_consent_transition,
    verify_history_compatibility,
)
from .competition_package import (
    CompetitionReleaseIdentity,
)
from .competition_receipt_store import publish_installation_receipt
from .competition_recovery import (
    RecoveryCheckpointBody,
    RecoveryLimits,
    VerifiedRecoveryCheckpoint,
    load_installed_retained_checkpoint_archive,
    load_retained_checkpoint_archive,
    validate_checkpoint_for_successor,
)
from .competition_supervisor import (
    MAX_SUCCESSOR_DOCUMENT_BYTES,
    MAX_SUCCESSOR_HISTORY_BYTES,
    SignedSuccessorSupervisorDirective,
    SuccessorSupervisorDirective,
    SuccessorSupervisorDirectivePage,
    SuccessorSupervisorDirectiveState,
    SuccessorSupervisorOperatorConsent,
    advance_successor_supervisor_directive_history_state,
    advance_successor_supervisor_directive_state,
    consent_for_retained_directive,
    load_bound_successor_replay_package,
    parse_canonical_successor_operator_consent,
    parse_canonical_successor_supervisor_directive_history,
    retained_directive_observation_block,
    successor_operator_consent_sha256,
    successor_source_config_sha256,
    verify_bound_successor_chain_authorization,
)
from .competition_weights import (
    SignedCompetitionWeightAuthorization,
    validate_runtime_execution_authorization,
)
from .competition_worker import CompetitionWorkerCapacity
from .encoding import account_id32
from .file_identity import file_fingerprint as _fingerprint
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import (
    MAX_JSON_SAFE_INTEGER,
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
    SignedSupervisorDirective,
    SupervisorDirectiveState,
    ValidatorSupervisorConfig,
    advance_supervisor_directive_history_state,
    parse_canonical_signed_supervisor_directive,
    parse_canonical_validator_supervisor_config,
)

if TYPE_CHECKING:
    from .competition_supervisor_observer import SuccessorHostObserverConfig
else:
    SuccessorHostObserverConfig = Any

SUCCESSOR_INSTALLATION_RECEIPT_SCHEMA = "umi-successor-installation-receipt/1"
SUCCESSOR_INSTALLATION_RECEIPT_DOMAIN = b"umi-successor-installation-receipt-v1\0"
MAX_SUCCESSOR_INSTALLATION_RECEIPT_BYTES = 1024 * 1024
MAX_SUCCESSOR_WORKER_EXECUTION_BYTES = 1024 * 1024
MAX_SUCCESSOR_WORKER_LIMITS_BYTES = 64 * 1024
MAX_SUCCESSOR_RELEASE_IDENTITY_BYTES = 64 * 1024
MAX_SUCCESSOR_HOST_OBSERVER_CONFIG_BYTES = 512 * 1024

ACTIVATION_MOUNT_ROOT = Path("/run/umi-successor-activation")
ANCHOR_DIRECTORY_NAME = "anchor"
CURRENT_DIRECTORY_NAME = "current"
INSTALLATION_RECEIPT_FILENAME = "installation-receipt.json"
SOURCE_CONFIG_FILENAME = "source-config.json"
OPERATOR_CONSENT_FILENAME = "operator-consent.json"
LEGACY_SIGNED_DIRECTIVE_FILENAME = "legacy-signed-directive.json"
INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME = "initial-successor-directive-page.json"
CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME = "current-successor-directive-page.json"
SIGNED_HOST_ARTIFACT_FILENAME = "signed-host-artifact.json"
RELEASE_IDENTITY_FILENAME = "release-identity.json"
WORKER_EXECUTION_FILENAME = "worker-execution.json"
WORKER_LIMITS_FILENAME = "worker-limits.json"
HOST_OBSERVER_FILENAME = "observer-config.json"
WEIGHT_AUTHORIZATION_FILENAME = "weight-authorization.json"
PACKAGE_DIRECTORY_NAME = "package"
RECOVERY_DIRECTORY_NAME = "recovery"

_ANCHOR_CONTROL_FILENAMES = frozenset(
    {
        INSTALLATION_RECEIPT_FILENAME,
        SOURCE_CONFIG_FILENAME,
        OPERATOR_CONSENT_FILENAME,
        LEGACY_SIGNED_DIRECTIVE_FILENAME,
        INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
        SIGNED_HOST_ARTIFACT_FILENAME,
        WORKER_LIMITS_FILENAME,
        HOST_OBSERVER_FILENAME,
    }
)
_CURRENT_CONTROL_FILENAMES = frozenset(
    {
        CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
        RELEASE_IDENTITY_FILENAME,
        WORKER_EXECUTION_FILENAME,
    }
)
_INSTALLATION_TOKEN = object()
_ACTIVATION_TOKEN = object()
_ModelT = TypeVar("_ModelT", bound=StrictProtocolModel)


class HostActivationError(ValueError):
    """A durable installation or running activation failed closed."""


class SuccessorWorkerExecutionLimits(StrictProtocolModel):
    """Immutable operator ceilings for rolling per-directive worker inputs."""

    schema_: Literal[
        "umi-successor-worker-execution-limits/1", "umi-successor-worker-execution-limits/2"
    ] = Field(alias="schema")
    replay_capacity_ceiling: CompetitionWorkerCapacity
    maximum_weight_attempts: Annotated[int, Field(ge=1, le=65_536)]
    maximum_weight_evidence_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)]
    maximum_submission_timeout_seconds: Annotated[int, Field(ge=1, le=3_600)]
    weight_evidence_storage: EvidenceStorageConfig | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.weight_evidence_storage is None:
            value.pop("weight_evidence_storage", None)
        return value

    @model_validator(mode="after")
    def storage_version(self) -> Self:
        if (self.weight_evidence_storage is not None) != (
            self.schema_ == "umi-successor-worker-execution-limits/2"
        ):
            raise ValueError("evidence storage requires versioned installed limits")
        return self


class SuccessorInstallationReceipt(StrictProtocolModel):
    """Root-owned seal of one stopped legacy-to-successor installation boundary."""

    schema_: Literal[
        SUCCESSOR_INSTALLATION_RECEIPT_SCHEMA, "umi-successor-installation-receipt/2"
    ] = Field(alias="schema")
    evidence_migration: EvidenceMigrationSeal | None = None

    @model_serializer(mode="wrap")
    def preserve_original_receipt(self, handler):
        value = handler(self)
        if self.evidence_migration is None:
            value.pop("evidence_migration", None)
        return value

    channel_id: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    target_platform: Literal["linux/amd64", "linux/arm64"]
    source_config_sha256: Hex32
    source_config_size_bytes: Annotated[int, Field(gt=0, le=MAX_SUPERVISOR_DOCUMENT_BYTES)]
    operator_consent_sha256: Hex32
    operator_consent_size_bytes: Annotated[int, Field(gt=0, le=MAX_SUCCESSOR_DOCUMENT_BYTES)]
    signed_host_artifact_sha256: Hex32
    signed_host_artifact_size_bytes: Annotated[int, Field(gt=0, le=32 * 1024**2)]
    host_manifest_sha256: Hex32
    host_umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    worker_limits_sha256: Hex32
    worker_limits_size_bytes: Annotated[int, Field(gt=0, le=MAX_SUCCESSOR_WORKER_LIMITS_BYTES)]
    host_observer_config_sha256: Hex32
    host_observer_config_size_bytes: Annotated[
        int, Field(gt=0, le=MAX_SUCCESSOR_HOST_OBSERVER_CONFIG_BYTES)
    ]
    initial_successor_page_sha256: Hex32
    initial_successor_page_size_bytes: Annotated[int, Field(gt=0, le=MAX_SUCCESSOR_HISTORY_BYTES)]
    legacy_installation_sha256: Hex32
    legacy_predecessor_sequence: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    legacy_predecessor_directive_sha256: Hex32
    legacy_predecessor_signed_directive_sha256: Hex32
    legacy_predecessor_signed_directive_size_bytes: Annotated[
        int, Field(gt=0, le=MAX_SUPERVISOR_DOCUMENT_BYTES)
    ]
    legacy_predecessor_accepted_at_finalized_block: Annotated[
        int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)
    ]
    legacy_predecessor_mode: Literal[
        "hold",
        "inactive_shadow",
        "bootstrap_service_weights",
        "translation_weights",
    ]
    legacy_predecessor_oci_manifest_sha256: Hex32 | None
    legacy_predecessor_operator_input_sha256: Hex32 | None
    checkpoint_sha256: Hex32
    checkpoint_finalized_block: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    checkpoint_finalized_block_hash: BlockHash
    checkpoint_genesis_hash: BlockHash
    checkpoint_chain_config_sha256: Hex32
    recovery_limits: RecoveryLimits
    chain_submission_authorized: Literal[False] = False

    @field_validator("validator_hotkey")
    @classmethod
    def valid_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if (self.evidence_migration is not None) != (
            self.schema_ == "umi-successor-installation-receipt/2"
        ):
            raise ValueError("migration requires version2 installation receipt")
        if self.checkpoint_finalized_block < self.legacy_predecessor_accepted_at_finalized_block:
            raise ValueError("installation checkpoint predates the legacy high-water mark")
        if (self.legacy_predecessor_mode == "hold") != (
            self.legacy_predecessor_oci_manifest_sha256 is None
        ):
            raise ValueError("installation receipt has an invalid legacy release binding")
        if (self.legacy_predecessor_mode == "bootstrap_service_weights") != (
            self.legacy_predecessor_operator_input_sha256 is not None
        ):
            raise ValueError("installation receipt has an invalid legacy input binding")
        return self


@dataclass(frozen=True, slots=True)
class RetainedRecoveryReference:
    checkpoint_sha256: str
    legacy_predecessor_directive_sha256: str
    finalized_block: int
    finalized_block_hash: str
    genesis_hash: str


@dataclass(frozen=True, slots=True)
class _MountedInputs:
    root: Path
    anchor_owner_uid: int
    current_owner_uid: int
    expected_current_entries: frozenset[str]
    anchor_sha256: dict[str, str]
    current_sha256: dict[str, str]
    root_identity: tuple[int, ...]
    anchor_identity: tuple[int, ...]
    current_identity: tuple[int, ...]
    # Captured around the full content verification. ctime is deliberately
    # included: restoring a file's contents, mode and mtime cannot restore this
    # snapshot. These tuples are process-local integrity, not signed authority.
    tree_snapshot: tuple[tuple[str, tuple[int, ...]], ...]

    def recheck(self, *, stable_installation_only: bool = False) -> None:
        _require_readonly_filesystem(self.root)
        _require_readonly_filesystem(self.root / ANCHOR_DIRECTORY_NAME)
        if not stable_installation_only:
            _require_readonly_filesystem(self.root / CURRENT_DIRECTORY_NAME)
        descriptor = _open_absolute_directory(self.root)
        try:
            info = os.fstat(descriptor)
            if _fingerprint(info)[:6] != self.root_identity[:6]:
                raise HostActivationError("successor activation mount identity changed")
            if _top_entries(descriptor) != {ANCHOR_DIRECTORY_NAME, CURRENT_DIRECTORY_NAME}:
                raise HostActivationError("successor activation mount entries changed")
        finally:
            os.close(descriptor)
        anchor = _open_absolute_directory(self.root / ANCHOR_DIRECTORY_NAME)
        try:
            info = os.fstat(anchor)
            if _fingerprint(info) != self.anchor_identity:
                raise HostActivationError("successor anchor mount identity changed")
            if _top_entries(anchor) != set(_ANCHOR_CONTROL_FILENAMES) | {RECOVERY_DIRECTORY_NAME}:
                raise HostActivationError("successor anchor entries changed")
            for name, expected_sha256 in self.anchor_sha256.items():
                payload = _read_control_at(
                    anchor, name, _control_limit(name), owner=self.anchor_owner_uid
                )
                if hashlib.sha256(payload).hexdigest() != expected_sha256:
                    raise HostActivationError("successor mounted control file changed")
        finally:
            os.close(anchor)
        if stable_installation_only:
            return
        current = _open_absolute_directory(self.root / CURRENT_DIRECTORY_NAME)
        try:
            info = os.fstat(current)
            if _fingerprint(info) != self.current_identity:
                raise HostActivationError("successor current mount identity changed")
            if _top_entries(current) != self.expected_current_entries:
                raise HostActivationError("successor current entries changed")
            for name, expected_sha256 in self.current_sha256.items():
                payload = _read_control_at(
                    current, name, _control_limit(name), owner=self.current_owner_uid
                )
                if hashlib.sha256(payload).hexdigest() != expected_sha256:
                    raise HostActivationError("successor current control file changed")
        finally:
            os.close(current)


@dataclass(frozen=True, slots=True)
class AuthenticatedSuccessorWorkerInputs:
    """Opaque, restart-recreatable worker inputs with no submission authority."""

    profile: Literal["competition_replay", "competition_weights"]
    validator_hotkey: str
    config_sha256: str
    directive_sha256: str
    package_sha256: str
    authorization_sha256: str | None
    release_identity: CompetitionReleaseIdentity
    authority_hotkeys: tuple[str, ...]
    config: ValidatorSupervisorConfig
    operator_consent: SuccessorSupervisorOperatorConsent
    v3_state: SupervisorDirectiveState
    v3_signed_bytes: bytes
    initial_page: SuccessorSupervisorDirectivePage
    current_page: SuccessorSupervisorDirectivePage
    signed_directive: SignedSuccessorSupervisorDirective
    accepted_state: SuccessorSupervisorDirectiveState
    worker_execution_limits: SuccessorWorkerExecutionLimits
    observer_config: SuccessorHostObserverConfig
    worker_execution_config: Any
    authorization: SignedCompetitionWeightAuthorization | None
    checkpoint_sha256: str
    checkpoint_finalized_block: int
    initial_accepted_at_finalized_block: int
    receipt_sha256: str
    host_manifest_sha256: str
    _receipt: SuccessorInstallationReceipt = field(repr=False, compare=False)
    _package_body_sha256: str = field(repr=False, compare=False)
    _recovery_body_sha256: str = field(repr=False, compare=False)
    _recovery_predecessor_sha256: str = field(repr=False, compare=False)
    _mount: _MountedInputs = field(repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _installation_binding: str = field(default="", repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    @property
    def directive(self) -> SuccessorSupervisorDirective:
        return self.signed_directive.directive

    @property
    def mount_root(self) -> Path:
        return self._mount.root

    def recheck(self) -> None:
        validate_authenticated_successor_worker_inputs(self)


@dataclass(frozen=True, slots=True)
class AuthenticatedSuccessorActivation:
    """Opaque active worker authority derived from installed inputs and finality."""

    profile: Literal["competition_replay", "competition_weights"]
    validator_hotkey: str
    config_sha256: str
    directive_sha256: str
    package_sha256: str
    authorization_sha256: str | None
    release_identity: CompetitionReleaseIdentity
    authority_hotkeys: tuple[str, ...]
    checkpoint_sha256: str
    accepted_state: SuccessorSupervisorDirectiveState
    signed_directive: SignedSuccessorSupervisorDirective
    finalized_block: int
    finalized_block_hash: str
    _inputs: AuthenticatedSuccessorWorkerInputs = field(repr=False, compare=False)
    _observation: Any = field(repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    @property
    def directive(self) -> SuccessorSupervisorDirective:
        return self.signed_directive.directive

    @property
    def worker_execution_config(self) -> Any:
        return self._inputs.worker_execution_config

    def recheck(self) -> None:
        validate_authenticated_successor_activation(
            self,
            validator_hotkey=self.validator_hotkey,
            directive_sha256=self.directive_sha256,
            package_sha256=self.package_sha256,
            authorization_sha256=self.authorization_sha256,
            expected_profile=self.profile,
        )

    def refresh(self, *, owned_observation: Any) -> AuthenticatedSuccessorActivation:
        """Reauthorize the same immutable inputs with new owned finality.

        The old proof may have expired during replay; it is never extended or
        reused as current authority. The new proof must not roll back/fork the
        prior head, and the signed directive must still be active at its block.
        """
        _validate_activation_binding(self)
        from .competition_chain_state import validate_owned_weight_observation

        validate_owned_weight_observation(owned_observation)
        if owned_observation.block < self.finalized_block or (
            owned_observation.block == self.finalized_block
            and owned_observation.block_hash != self.finalized_block_hash
        ):
            raise HostActivationError("successor activation refresh rolled back or forked")
        return activate_successor_worker(self._inputs, owned_observation=owned_observation)

    def validate_retained_recovery(
        self,
        checkpoint_sha256: str,
        validator_hotkey: str,
        current_directive_predecessor: str,
    ) -> RetainedRecoveryReference:
        self.recheck()
        receipt = self._inputs._receipt
        if (
            not hmac.compare_digest(checkpoint_sha256, self.checkpoint_sha256)
            or account_id32(validator_hotkey) != account_id32(self.validator_hotkey)
            or not hmac.compare_digest(
                current_directive_predecessor,
                self.directive.previous_directive_sha256,
            )
            or self.accepted_state.transition_v3_directive_sha256
            != receipt.legacy_predecessor_directive_sha256
            or self._inputs._recovery_predecessor_sha256
            != receipt.legacy_predecessor_directive_sha256
        ):
            raise HostActivationError("successor retained recovery binding changed")
        return RetainedRecoveryReference(
            checkpoint_sha256=self.checkpoint_sha256,
            legacy_predecessor_directive_sha256=(receipt.legacy_predecessor_directive_sha256),
            finalized_block=receipt.checkpoint_finalized_block,
            finalized_block_hash=receipt.checkpoint_finalized_block_hash,
            genesis_hash=receipt.checkpoint_genesis_hash,
        )


def successor_installation_receipt_sha256(receipt: SuccessorInstallationReceipt) -> str:
    receipt = _canonical(SuccessorInstallationReceipt, receipt)
    return hashlib.sha256(
        SUCCESSOR_INSTALLATION_RECEIPT_DOMAIN + canonical_json_bytes(receipt)
    ).hexdigest()


def parse_canonical_successor_installation_receipt(
    payload: bytes,
) -> SuccessorInstallationReceipt:
    value = _parse_canonical_json(
        payload,
        maximum_bytes=MAX_SUCCESSOR_INSTALLATION_RECEIPT_BYTES,
        label="successor installation receipt",
    )
    try:
        receipt = SuccessorInstallationReceipt.model_validate(value)
    except Exception as error:
        raise HostActivationError("successor installation receipt schema is invalid") from error
    if canonical_json_bytes(receipt) != payload:
        raise HostActivationError("successor installation receipt is not canonical")
    return receipt


def seal_successor_installation_receipt(
    receipt_path: Path,
    *,
    config_path: Path,
    operator_consent_path: Path,
    legacy_signed_directive_path: Path,
    initial_successor_page_path: Path,
    signed_host_artifact_path: Path,
    worker_limits_path: Path,
    host_observer_config_path: Path,
    recovery_archive_path: Path,
    recovery_limits: RecoveryLimits,
    verified_host_tree: Any,
    verified_checkpoint: VerifiedRecoveryCheckpoint,
) -> SuccessorInstallationReceipt:
    """Write one immutable receipt while both stopped-host capabilities remain live."""

    _require_root_linux()
    config_bytes = _read_root_control_path(
        config_path,
        MAX_SUPERVISOR_DOCUMENT_BYTES,
        modes={0o400, 0o440, 0o444, 0o600, 0o640},
    )
    consent_bytes = _read_root_control_path(
        operator_consent_path,
        MAX_SUCCESSOR_DOCUMENT_BYTES,
        modes={0o400, 0o440, 0o444},
    )
    legacy_bytes = _read_root_control_path(
        legacy_signed_directive_path,
        MAX_SUPERVISOR_DOCUMENT_BYTES,
        modes={0o400, 0o440, 0o444},
    )
    initial_page_bytes = _read_root_control_path(
        initial_successor_page_path,
        MAX_SUCCESSOR_HISTORY_BYTES,
        modes={0o400, 0o440, 0o444},
    )
    host_bytes = _read_root_control_path(
        signed_host_artifact_path,
        32 * 1024**2,
        modes={0o400, 0o440, 0o444},
    )
    worker_limits_bytes = _read_root_control_path(
        worker_limits_path,
        MAX_SUCCESSOR_WORKER_LIMITS_BYTES,
        modes={0o400, 0o440, 0o444},
    )
    observer_config_bytes = _read_root_control_path(
        host_observer_config_path,
        MAX_SUCCESSOR_HOST_OBSERVER_CONFIG_BYTES,
        modes={0o400, 0o440, 0o444},
    )
    config = parse_canonical_validator_supervisor_config(config_bytes)
    consent = parse_canonical_successor_operator_consent(consent_bytes)
    legacy_signed = parse_canonical_signed_supervisor_directive(legacy_bytes)
    _parse_worker_execution_limits(worker_limits_bytes)
    observer_config = _parse_host_observer_config(observer_config_bytes)
    host_signed = _parse_and_verify_host_artifact(
        host_bytes,
        config=config,
        expected_manifest_sha256=consent.approved_host_manifest_sha256,
    )
    tree = _validate_host_tree_capability(
        verified_host_tree,
        manifest_sha256=host_signed.manifest_sha256,
        target_platform=config.target_platform,
        revision=host_signed.manifest.umi_git_revision,
    )
    checkpoint = _validate_checkpoint_capability(
        verified_checkpoint,
        config=config,
        consent=consent,
    )
    _verify_host_observer_config(
        observer_config,
        config=config,
        checkpoint_genesis_hash=checkpoint.genesis_hash,
    )
    v3_state = _legacy_state(config, consent, legacy_signed)
    if (
        advance_supervisor_directive_history_state(
            legacy_signed,
            config=config,
            finalized_block=checkpoint.finalized_block,
            prior_state=v3_state,
        )
        != v3_state
    ):
        raise HostActivationError("legacy signed directive differs from its high-water state")
    initial_page = parse_canonical_successor_supervisor_directive_history(initial_page_bytes)
    _verify_initial_successor_history(
        initial_page,
        config=config,
        consent=consent,
        v3_state=v3_state,
        legacy_signed_bytes=legacy_bytes,
        accepted_block=checkpoint.finalized_block,
    )
    archive_body, _ = load_retained_checkpoint_archive(
        recovery_archive_path,
        expected_sha256=checkpoint.checkpoint_sha256,
        owner=checkpoint._stopped.service_uid,
        limits=recovery_limits,
    )
    if archive_body != checkpoint._body:
        raise HostActivationError("recovery archive differs from the verified checkpoint")
    receipt = SuccessorInstallationReceipt(
        schema=SUCCESSOR_INSTALLATION_RECEIPT_SCHEMA,
        channel_id=config.channel_id,
        validator_hotkey=config.validator_hotkey,
        target_platform=config.target_platform,
        source_config_sha256=successor_source_config_sha256(config),
        source_config_size_bytes=len(config_bytes),
        operator_consent_sha256=successor_operator_consent_sha256(consent),
        operator_consent_size_bytes=len(consent_bytes),
        signed_host_artifact_sha256=hashlib.sha256(host_bytes).hexdigest(),
        signed_host_artifact_size_bytes=len(host_bytes),
        host_manifest_sha256=host_signed.manifest_sha256,
        host_umi_git_revision=host_signed.manifest.umi_git_revision,
        worker_limits_sha256=hashlib.sha256(worker_limits_bytes).hexdigest(),
        worker_limits_size_bytes=len(worker_limits_bytes),
        host_observer_config_sha256=hashlib.sha256(observer_config_bytes).hexdigest(),
        host_observer_config_size_bytes=len(observer_config_bytes),
        initial_successor_page_sha256=hashlib.sha256(initial_page_bytes).hexdigest(),
        initial_successor_page_size_bytes=len(initial_page_bytes),
        legacy_installation_sha256=checkpoint.installation_sha256,
        legacy_predecessor_sequence=v3_state.accepted_sequence,
        legacy_predecessor_directive_sha256=v3_state.accepted_directive_sha256,
        legacy_predecessor_signed_directive_sha256=hashlib.sha256(legacy_bytes).hexdigest(),
        legacy_predecessor_signed_directive_size_bytes=len(legacy_bytes),
        legacy_predecessor_accepted_at_finalized_block=(v3_state.accepted_at_finalized_block),
        legacy_predecessor_mode=v3_state.accepted_mode,
        legacy_predecessor_oci_manifest_sha256=v3_state.accepted_oci_manifest_sha256,
        legacy_predecessor_operator_input_sha256=v3_state.accepted_operator_input_sha256,
        checkpoint_sha256=checkpoint.checkpoint_sha256,
        checkpoint_finalized_block=checkpoint.finalized_block,
        checkpoint_finalized_block_hash=checkpoint.finalized_block_hash,
        checkpoint_genesis_hash=checkpoint.genesis_hash,
        checkpoint_chain_config_sha256=checkpoint._body.chain_config_sha256,
        recovery_limits=_canonical(RecoveryLimits, recovery_limits),
    )
    payload = canonical_json_bytes(receipt)
    _write_root_receipt_once(receipt_path, payload)
    tree.recheck()
    validate_checkpoint_for_successor(
        checkpoint,
        validator_hotkey=receipt.validator_hotkey,
        predecessor_directive_sha256=receipt.legacy_predecessor_directive_sha256,
        minimum_finalized_block=receipt.legacy_predecessor_accepted_at_finalized_block,
    )
    loaded_body, _ = load_retained_checkpoint_archive(
        recovery_archive_path,
        expected_sha256=receipt.checkpoint_sha256,
        owner=checkpoint._stopped.service_uid,
        limits=receipt.recovery_limits,
    )
    if loaded_body != archive_body:
        raise HostActivationError("recovery archive changed while sealing installation")
    if (
        parse_canonical_successor_installation_receipt(
            _read_root_control_path(
                receipt_path,
                MAX_SUCCESSOR_INSTALLATION_RECEIPT_BYTES,
                modes={0o400, 0o440, 0o444},
            )
        )
        != receipt
    ):
        raise HostActivationError("installation receipt readback mismatch")
    return receipt


def load_successor_worker_inputs() -> AuthenticatedSuccessorWorkerInputs:
    """Fully verify fixed mounts before collecting a fresh chain observation.

    The returned non-authorizing capability retains authenticated digests and
    immutable inode identities. Its rechecks do not repeat package replay.
    """

    root = ACTIVATION_MOUNT_ROOT
    _require_readonly_filesystem(root)
    _require_readonly_filesystem(root / ANCHOR_DIRECTORY_NAME)
    _require_readonly_filesystem(root / CURRENT_DIRECTORY_NAME)
    root_fd = _open_absolute_directory(root)
    anchor_fd = -1
    current_fd = -1
    try:
        root_info = os.fstat(root_fd)
        if root_info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(root_info.st_mode) != 0o555:
            raise HostActivationError("successor activation mount root is not immutable")
        if _top_entries(root_fd) != {ANCHOR_DIRECTORY_NAME, CURRENT_DIRECTORY_NAME}:
            raise HostActivationError("successor activation mount has an unexpected file set")
        anchor_fd = _open_child_directory_at(root_fd, ANCHOR_DIRECTORY_NAME)
        current_fd = _open_child_directory_at(root_fd, CURRENT_DIRECTORY_NAME)
        anchor_info = os.fstat(anchor_fd)
        current_info = os.fstat(current_fd)
        anchor_owner = anchor_info.st_uid
        current_owner = current_info.st_uid
        if (
            not _valid_anchor_mount_owner(anchor_owner)
            or stat.S_IMODE(anchor_info.st_mode) != 0o555
        ):
            raise HostActivationError("successor anchor mount owner or mode is unsafe")
        if current_owner != os.geteuid() or stat.S_IMODE(current_info.st_mode) != 0o555:
            raise HostActivationError("successor current mount owner or mode is unsafe")
        if _top_entries(anchor_fd) != set(_ANCHOR_CONTROL_FILENAMES) | {RECOVERY_DIRECTORY_NAME}:
            raise HostActivationError("successor anchor mount has an unexpected file set")
        receipt_bytes = _read_control_at(
            anchor_fd,
            INSTALLATION_RECEIPT_FILENAME,
            MAX_SUCCESSOR_INSTALLATION_RECEIPT_BYTES,
            owner=anchor_owner,
        )
        receipt = parse_canonical_successor_installation_receipt(receipt_bytes)
        # Snapshot before reading/replaying the remaining files, then require
        # precisely these inodes and metadata after all hashes are verified.
        tree_snapshot = _snapshot_mounted_tree(root, receipt.recovery_limits)
        anchor_control = _read_bound_controls(anchor_fd, receipt, owner=anchor_owner)
        current_control = _read_current_controls(current_fd, owner=current_owner)
        root_identity = _fingerprint(root_info)
        anchor_identity = _fingerprint(anchor_info)
        current_identity = _fingerprint(current_info)
    finally:
        if current_fd >= 0:
            os.close(current_fd)
        if anchor_fd >= 0:
            os.close(anchor_fd)
        os.close(root_fd)
    control = {**anchor_control, **current_control}
    config = parse_canonical_validator_supervisor_config(control[SOURCE_CONFIG_FILENAME])
    consent = parse_canonical_successor_operator_consent(control[OPERATOR_CONSENT_FILENAME])
    legacy_signed = parse_canonical_signed_supervisor_directive(
        control[LEGACY_SIGNED_DIRECTIVE_FILENAME]
    )
    worker_execution = _parse_worker_execution_config(control[WORKER_EXECUTION_FILENAME])
    worker_limits = _parse_worker_execution_limits(control[WORKER_LIMITS_FILENAME])
    observer_config = _parse_host_observer_config(control[HOST_OBSERVER_FILENAME])
    _verify_receipt_controls(
        receipt,
        config=config,
        consent=consent,
        legacy_signed=legacy_signed,
        host_bytes=control[SIGNED_HOST_ARTIFACT_FILENAME],
        worker_limits_bytes=control[WORKER_LIMITS_FILENAME],
        observer_config_bytes=control[HOST_OBSERVER_FILENAME],
    )
    initial_page = parse_canonical_successor_supervisor_directive_history(
        control[INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME]
    )
    current_page = parse_canonical_successor_supervisor_directive_history(
        control[CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME]
    )
    if consent.history_compatibility is not None:
        boundary = consent.history_compatibility.body
        retained = [
            item
            for item in [*initial_page.directives, *current_page.directives]
            if item.directive.sequence <= boundary.predecessor_sequence
        ]
        if (
            not retained
            or retained[-1].directive_sha256 != boundary.predecessor_directive_sha256
            or hashlib.sha256(
                canonical_json_bytes(
                    [item.model_dump(mode="json", by_alias=True) for item in retained]
                )
            ).hexdigest()
            != boundary.retained_history_sha256
        ):
            raise HostActivationError(
                "retained signed history differs from migration authorization"
            )
    v3_state = _legacy_state(config, consent, legacy_signed)
    initial_state = _verify_initial_successor_history(
        initial_page,
        config=config,
        consent=consent,
        v3_state=v3_state,
        legacy_signed_bytes=control[LEGACY_SIGNED_DIRECTIVE_FILENAME],
        accepted_block=receipt.checkpoint_finalized_block,
    )
    accepted_state = _verify_staged_current_history(
        current_page,
        config=config,
        consent=consent,
        initial_state=initial_state,
    )
    head = current_page.head
    directive = head.directive
    expected_current_entries = set(_CURRENT_CONTROL_FILENAMES) | {PACKAGE_DIRECTORY_NAME}
    if directive.mode == "competition_weights":
        expected_current_entries.add(WEIGHT_AUTHORIZATION_FILENAME)
    elif directive.mode != "competition_replay":
        raise HostActivationError("successor worker mount selected a non-worker directive")
    current_fd = _open_absolute_directory(root / CURRENT_DIRECTORY_NAME)
    try:
        observed_current_entries = _top_entries(current_fd)
    finally:
        os.close(current_fd)
    if observed_current_entries != expected_current_entries:
        raise HostActivationError("successor activation mount has an unexpected file set")
    release_identity = _parse_release_identity(control[RELEASE_IDENTITY_FILENAME])
    package = load_bound_successor_replay_package(
        root / CURRENT_DIRECTORY_NAME / PACKAGE_DIRECTORY_NAME,
        directive=directive,
        observed_release=release_identity,
    )
    authorization = None
    authorization_sha256 = None
    authorization_body = None
    if directive.mode == "competition_weights":
        authorization_bytes = _read_mounted_control_file(
            root / CURRENT_DIRECTORY_NAME / WEIGHT_AUTHORIZATION_FILENAME,
            directive.chain_authorization.authorization_size_bytes,
            owner=current_owner,
        )
        authorization_body = verify_bound_successor_chain_authorization(
            authorization_bytes,
            directive=directive,
            config=config,
            package=package,
        )
        authorization = SignedCompetitionWeightAuthorization.model_validate_json(
            authorization_bytes, strict=True
        )
        authorization_sha256 = hashlib.sha256(authorization_bytes).hexdigest()
    _validate_worker_execution_bindings(
        worker_execution,
        directive=directive,
        release_identity=release_identity,
        authorization_body=authorization_body,
        limits=worker_limits,
    )
    recovery_body, _ = load_installed_retained_checkpoint_archive(
        root / ANCHOR_DIRECTORY_NAME / RECOVERY_DIRECTORY_NAME / receipt.checkpoint_sha256,
        expected_sha256=receipt.checkpoint_sha256,
        owner=anchor_owner,
        limits=receipt.recovery_limits,
    )
    _verify_retained_recovery_body(receipt, recovery_body)
    anchor_sha256 = {
        name: hashlib.sha256(payload).hexdigest() for name, payload in anchor_control.items()
    }
    anchor_sha256[INSTALLATION_RECEIPT_FILENAME] = hashlib.sha256(receipt_bytes).hexdigest()
    current_sha256 = {
        name: hashlib.sha256(payload).hexdigest() for name, payload in current_control.items()
    }
    if authorization is not None:
        current_sha256[WEIGHT_AUTHORIZATION_FILENAME] = authorization_sha256
    mount = _MountedInputs(
        root,
        anchor_owner,
        current_owner,
        frozenset(expected_current_entries),
        anchor_sha256,
        current_sha256,
        root_identity,
        anchor_identity,
        current_identity,
        tree_snapshot,
    )
    mount.recheck()
    if _snapshot_mounted_tree(root, receipt.recovery_limits) != tree_snapshot:
        raise HostActivationError("successor activation tree changed during verification")
    inputs = AuthenticatedSuccessorWorkerInputs(
        profile=directive.mode,
        validator_hotkey=config.validator_hotkey,
        config_sha256=receipt.source_config_sha256,
        directive_sha256=head.directive_sha256,
        package_sha256=package.package_sha256,
        authorization_sha256=authorization_sha256,
        release_identity=release_identity,
        authority_hotkeys=tuple(item.hotkey for item in config.trusted_authorities),
        config=config,
        operator_consent=consent,
        v3_state=v3_state,
        v3_signed_bytes=control[LEGACY_SIGNED_DIRECTIVE_FILENAME],
        initial_page=initial_page,
        current_page=current_page,
        signed_directive=head,
        accepted_state=accepted_state,
        worker_execution_limits=worker_limits,
        observer_config=observer_config,
        worker_execution_config=worker_execution,
        authorization=authorization,
        checkpoint_sha256=receipt.checkpoint_sha256,
        checkpoint_finalized_block=receipt.checkpoint_finalized_block,
        initial_accepted_at_finalized_block=receipt.checkpoint_finalized_block,
        receipt_sha256=successor_installation_receipt_sha256(receipt),
        host_manifest_sha256=receipt.host_manifest_sha256,
        _receipt=receipt,
        _package_body_sha256=hashlib.sha256(canonical_json_bytes(package)).hexdigest(),
        _recovery_body_sha256=hashlib.sha256(canonical_json_bytes(recovery_body)).hexdigest(),
        _recovery_predecessor_sha256=(recovery_body.legacy_snapshot.accepted_directive_sha256),
        _mount=mount,
        _issuer=_INSTALLATION_TOKEN,
    )
    object.__setattr__(inputs, "_installation_binding", _installation_binding(inputs))
    object.__setattr__(inputs, "_binding", _worker_inputs_binding(inputs))
    inputs.recheck()
    return inputs


load_authenticated_successor_installation = load_successor_worker_inputs


def validate_authenticated_successor_worker_inputs(
    inputs: AuthenticatedSuccessorWorkerInputs,
) -> None:
    _validate_input_capability_binding(inputs)
    if inputs._binding != _worker_inputs_binding(inputs):
        raise HostActivationError("successor worker inputs are absent or altered")
    _recheck_verified_tree(inputs, stable_installation_only=False)


def validate_authenticated_successor_installation(
    inputs: AuthenticatedSuccessorWorkerInputs,
) -> None:
    """Recheck the immutable transition anchor, not the rolling v4 cursor."""

    _validate_input_capability_binding(inputs)
    _recheck_verified_tree(inputs, stable_installation_only=True)


def _validate_input_capability_binding(inputs: AuthenticatedSuccessorWorkerInputs) -> None:
    if (
        type(inputs) is not AuthenticatedSuccessorWorkerInputs
        or inputs._issuer is not _INSTALLATION_TOKEN
        or inputs._installation_binding != _installation_binding(inputs)
    ):
        raise HostActivationError("successor installation capability is absent or altered")


def _recheck_verified_tree(
    inputs: AuthenticatedSuccessorWorkerInputs, *, stable_installation_only: bool
) -> None:
    expected = inputs._mount.tree_snapshot
    if stable_installation_only:
        expected = tuple(item for item in expected if not item[0].startswith("current"))
    observed = _snapshot_mounted_tree(
        inputs._mount.root,
        inputs._receipt.recovery_limits,
        stable_installation_only=stable_installation_only,
    )
    if observed != expected:
        raise HostActivationError("verified successor activation tree changed")


def activate_successor_worker(
    inputs: AuthenticatedSuccessorWorkerInputs,
    *,
    owned_observation: Any | None = None,
) -> AuthenticatedSuccessorActivation:
    """Mint active authority; weights require a fresh owned finality capability."""

    validate_authenticated_successor_worker_inputs(inputs)
    if owned_observation is None:
        if inputs.profile != "competition_replay":
            raise HostActivationError("successor weights require owned finalized observation")
        if inputs.current_page.directives:
            raise HostActivationError(
                "rolling successor history requires an owned finalized observation"
            )
        finalized_block = inputs._receipt.checkpoint_finalized_block
        finalized_hash = inputs._receipt.checkpoint_finalized_block_hash
    else:
        from .competition_chain_state import validate_owned_weight_observation

        try:
            validate_owned_weight_observation(owned_observation)
        except (TypeError, ValueError) as error:
            raise HostActivationError("successor activation observation is not owned") from error
        if (
            account_id32(owned_observation.validator_hotkey)
            != account_id32(inputs.validator_hotkey)
            or owned_observation.genesis_hash != inputs._receipt.checkpoint_genesis_hash
            or owned_observation.block < inputs._receipt.checkpoint_finalized_block
        ):
            raise HostActivationError("successor activation observation binding changed")
        finalized_block = owned_observation.block
        finalized_hash = owned_observation.block_hash
    state = _advance_active_successor_history(
        inputs.initial_page,
        inputs.current_page,
        config=inputs.config,
        consent=inputs.operator_consent,
        v3_state=inputs.v3_state,
        legacy_signed_bytes=inputs.v3_signed_bytes,
        finalized_block=finalized_block,
    )
    if state.accepted_directive_sha256 != inputs.directive_sha256:
        raise HostActivationError("active successor state does not reach the mounted head")
    activation = AuthenticatedSuccessorActivation(
        profile=inputs.profile,
        validator_hotkey=inputs.validator_hotkey,
        config_sha256=inputs.config_sha256,
        directive_sha256=inputs.directive_sha256,
        package_sha256=inputs.package_sha256,
        authorization_sha256=inputs.authorization_sha256,
        release_identity=inputs.release_identity,
        authority_hotkeys=inputs.authority_hotkeys,
        checkpoint_sha256=inputs.checkpoint_sha256,
        accepted_state=state,
        signed_directive=inputs.signed_directive,
        finalized_block=finalized_block,
        finalized_block_hash=finalized_hash,
        _inputs=inputs,
        _observation=owned_observation,
        _issuer=_ACTIVATION_TOKEN,
    )
    object.__setattr__(activation, "_binding", _activation_binding(activation))
    activation.recheck()
    return activation


def load_authenticated_successor_activation(
    *,
    owned_observation: Any | None = None,
) -> AuthenticatedSuccessorActivation:
    """Load and activate once; an expired supplied observation still fails.

    Production callers should load inputs before collecting finality, then
    call activate_successor_worker with those verified inputs. Loading here
    necessarily includes the full bounded package verification.
    """
    return activate_successor_worker(
        load_successor_worker_inputs(),
        owned_observation=owned_observation,
    )


def validate_authenticated_successor_activation(
    activation: AuthenticatedSuccessorActivation,
    *,
    validator_hotkey: str,
    directive_sha256: str,
    package_sha256: str,
    authorization_sha256: str | None,
    expected_profile: Literal["competition_replay", "competition_weights"],
) -> None:
    _validate_activation_binding(activation)
    validate_authenticated_successor_worker_inputs(activation._inputs)
    if activation._observation is not None:
        from .competition_chain_state import validate_owned_weight_observation

        try:
            validate_owned_weight_observation(activation._observation)
        except (TypeError, ValueError) as error:
            raise HostActivationError("successor activation observation expired") from error
    if (
        account_id32(validator_hotkey) != account_id32(activation.validator_hotkey)
        or not hmac.compare_digest(directive_sha256, activation.directive_sha256)
        or not hmac.compare_digest(package_sha256, activation.package_sha256)
        or authorization_sha256 != activation.authorization_sha256
        or expected_profile != activation.profile
    ):
        raise HostActivationError("successor activation use differs from authenticated inputs")


def _validate_activation_binding(activation: AuthenticatedSuccessorActivation) -> None:
    if (
        type(activation) is not AuthenticatedSuccessorActivation
        or activation._issuer is not _ACTIVATION_TOKEN
        or activation._binding != _activation_binding(activation)
    ):
        raise HostActivationError("successor activation capability is absent or altered")


def _validate_host_tree_capability(
    tree: Any,
    *,
    manifest_sha256: str,
    target_platform: str,
    revision: str,
) -> Any:
    from .competition_host_artifacts import VerifiedHostTree

    if type(tree) is not VerifiedHostTree:
        raise HostActivationError("installation requires a verified successor host tree")
    tree.recheck()
    if (
        tree.manifest_sha256 != manifest_sha256
        or tree.target_platform != target_platform
        or tree.umi_git_revision != revision
    ):
        raise HostActivationError("verified successor host tree binding changed")
    return tree


def _validate_checkpoint_capability(
    checkpoint: VerifiedRecoveryCheckpoint,
    *,
    config: ValidatorSupervisorConfig,
    consent: SuccessorSupervisorOperatorConsent,
) -> VerifiedRecoveryCheckpoint:
    if consent.history_compatibility is not None:
        raise HostActivationError("history migration requires its own stopped v4 seal")
    if type(checkpoint) is not VerifiedRecoveryCheckpoint:
        raise HostActivationError("installation requires a verified recovery checkpoint")
    if (
        consent.source_config_sha256 != successor_source_config_sha256(config)
        or consent.channel_id != config.channel_id
        or account_id32(consent.validator_hotkey) != account_id32(config.validator_hotkey)
        or consent.target_platform != config.target_platform
    ):
        raise HostActivationError("operator consent differs from installed legacy config")
    try:
        validate_checkpoint_for_successor(
            checkpoint,
            validator_hotkey=config.validator_hotkey,
            predecessor_directive_sha256=consent.predecessor_directive_sha256,
            minimum_finalized_block=consent.predecessor_accepted_at_finalized_block,
        )
    except (TypeError, ValueError) as error:
        raise HostActivationError("recovery checkpoint is not a live stopped capability") from error
    body = checkpoint._body
    if (
        checkpoint.accepted_sequence != consent.predecessor_sequence
        or checkpoint.accepted_directive_sha256 != consent.predecessor_directive_sha256
        or checkpoint.finalized_block < consent.authorized_at_finalized_block
        or checkpoint.finalized_block > consent.valid_through_block
        or body.legacy_snapshot.config_sha256 != successor_source_config_sha256(config)
    ):
        raise HostActivationError("recovery checkpoint differs from operator consent")
    return checkpoint


def _legacy_state(
    config: ValidatorSupervisorConfig,
    consent: SuccessorSupervisorOperatorConsent,
    signed: SignedSupervisorDirective,
) -> SupervisorDirectiveState:
    directive = signed.directive
    release = directive.release
    inputs = directive.operator_inputs
    if (
        directive.channel_id != config.channel_id
        or signed.directive_sha256 != consent.predecessor_directive_sha256
        or directive.sequence != consent.predecessor_sequence
        or hashlib.sha256(canonical_json_bytes(signed)).hexdigest()
        != consent.predecessor_signed_directive_sha256
    ):
        raise HostActivationError("legacy signed directive differs from operator consent")
    return SupervisorDirectiveState(
        schema=SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
        channel_id=config.channel_id,
        accepted_sequence=directive.sequence,
        accepted_directive_sha256=signed.directive_sha256,
        accepted_at_finalized_block=consent.predecessor_accepted_at_finalized_block,
        accepted_mode=directive.mode,
        accepted_oci_manifest_sha256=(None if release is None else release.oci_manifest_sha256),
        accepted_operator_input_sha256=(None if inputs is None else inputs.bundle_sha256),
    )


def _verify_initial_successor_history(
    page: SuccessorSupervisorDirectivePage,
    *,
    config: ValidatorSupervisorConfig,
    consent: SuccessorSupervisorOperatorConsent,
    v3_state: SupervisorDirectiveState,
    legacy_signed_bytes: bytes,
    accepted_block: int,
) -> SuccessorSupervisorDirectiveState:
    if (
        page.after_version != 3
        or page.after_sequence != v3_state.accepted_sequence
        or page.after_directive_sha256 != v3_state.accepted_directive_sha256
        or page.more
        or not page.directives
    ):
        raise HostActivationError("initial successor history does not start at the v3 anchor")
    state: SupervisorDirectiveState | SuccessorSupervisorDirectiveState = v3_state
    final_index = len(page.directives) - 1
    for index, signed in enumerate(page.directives):
        function = (
            advance_successor_supervisor_directive_state
            if index == final_index and consent.history_compatibility is None
            else advance_successor_supervisor_directive_history_state
        )
        state = function(
            signed,
            config=config,
            operator_consent=consent,
            finalized_block=accepted_block,
            prior_state=state,
            prior_v3_signed_bytes=legacy_signed_bytes if index == 0 else None,
        )
    assert isinstance(state, SuccessorSupervisorDirectiveState)
    return state


def _verify_staged_current_history(
    page: SuccessorSupervisorDirectivePage,
    *,
    config: ValidatorSupervisorConfig,
    consent: SuccessorSupervisorOperatorConsent,
    initial_state: SuccessorSupervisorDirectiveState,
) -> SuccessorSupervisorDirectiveState:
    if (
        page.after_version != 4
        or page.after_sequence != initial_state.accepted_sequence
        or page.after_directive_sha256 != initial_state.accepted_directive_sha256
        or page.more
    ):
        raise HostActivationError("current successor history does not follow the initial anchor")
    state = initial_state
    for signed in page.directives:
        directive = signed.directive
        logical_block = retained_directive_observation_block(consent, directive, state)
        state = advance_successor_supervisor_directive_history_state(
            signed,
            config=config,
            operator_consent=consent,
            finalized_block=logical_block,
            prior_state=state,
        )
    return state


def _advance_active_successor_history(
    initial_page: SuccessorSupervisorDirectivePage,
    current_page: SuccessorSupervisorDirectivePage,
    *,
    config: ValidatorSupervisorConfig,
    consent: SuccessorSupervisorOperatorConsent,
    v3_state: SupervisorDirectiveState,
    legacy_signed_bytes: bytes,
    finalized_block: int,
) -> SuccessorSupervisorDirectiveState:
    if consent.history_compatibility is not None:
        state = v3_state
        for index, signed in enumerate([*initial_page.directives, *current_page.directives]):
            state = advance_successor_supervisor_directive_history_state(
                signed,
                config=config,
                operator_consent=consent,
                finalized_block=retained_directive_observation_block(
                    consent, signed.directive, state
                ),
                prior_state=state,
                prior_v3_signed_bytes=legacy_signed_bytes if index == 0 else None,
            )
        return advance_successor_supervisor_directive_state(
            signed,
            config=config,
            operator_consent=consent,
            finalized_block=finalized_block,
            prior_state=state,
        )
    state: SupervisorDirectiveState | SuccessorSupervisorDirectiveState = v3_state
    directives = [*initial_page.directives, *current_page.directives]
    final_index = len(directives) - 1
    for index, signed in enumerate(directives):
        function = (
            advance_successor_supervisor_directive_state
            if index == final_index
            else advance_successor_supervisor_directive_history_state
        )
        state = function(
            signed,
            config=config,
            operator_consent=consent,
            finalized_block=finalized_block,
            prior_state=state,
            prior_v3_signed_bytes=legacy_signed_bytes if index == 0 else None,
        )
    assert isinstance(state, SuccessorSupervisorDirectiveState)
    return state


def _verify_receipt_controls(
    receipt: SuccessorInstallationReceipt,
    *,
    config: ValidatorSupervisorConfig,
    consent: SuccessorSupervisorOperatorConsent,
    legacy_signed: SignedSupervisorDirective,
    host_bytes: bytes,
    worker_limits_bytes: bytes,
    observer_config_bytes: bytes,
) -> None:
    host = _parse_and_verify_host_artifact(
        host_bytes,
        config=config,
        expected_manifest_sha256=receipt.host_manifest_sha256,
    )
    v3_state = _legacy_state(config, consent, legacy_signed)
    observer_config = _parse_host_observer_config(observer_config_bytes)
    _verify_host_observer_config(
        observer_config,
        config=config,
        checkpoint_genesis_hash=receipt.checkpoint_genesis_hash,
    )
    observed = (
        config.channel_id,
        account_id32(config.validator_hotkey),
        config.target_platform,
        successor_source_config_sha256(config),
        successor_operator_consent_sha256(consent),
        hashlib.sha256(host_bytes).hexdigest(),
        host.manifest_sha256,
        host.manifest.umi_git_revision,
        hashlib.sha256(worker_limits_bytes).hexdigest(),
        hashlib.sha256(observer_config_bytes).hexdigest(),
        v3_state.accepted_sequence,
        v3_state.accepted_directive_sha256,
        hashlib.sha256(canonical_json_bytes(legacy_signed)).hexdigest(),
        v3_state.accepted_at_finalized_block,
        v3_state.accepted_mode,
        v3_state.accepted_oci_manifest_sha256,
        v3_state.accepted_operator_input_sha256,
    )
    expected = (
        receipt.channel_id,
        account_id32(receipt.validator_hotkey),
        receipt.target_platform,
        receipt.source_config_sha256,
        receipt.operator_consent_sha256,
        receipt.signed_host_artifact_sha256,
        receipt.host_manifest_sha256,
        receipt.host_umi_git_revision,
        receipt.worker_limits_sha256,
        receipt.host_observer_config_sha256,
        receipt.legacy_predecessor_sequence,
        receipt.legacy_predecessor_directive_sha256,
        receipt.legacy_predecessor_signed_directive_sha256,
        receipt.legacy_predecessor_accepted_at_finalized_block,
        receipt.legacy_predecessor_mode,
        receipt.legacy_predecessor_oci_manifest_sha256,
        receipt.legacy_predecessor_operator_input_sha256,
    )
    if observed != expected:
        raise HostActivationError("mounted controls differ from installation receipt")
    validate_evidence_migration_receipt(
        receipt, config=config, consent=consent, worker_limits_bytes=worker_limits_bytes
    )


def _verify_retained_recovery_body(
    receipt: SuccessorInstallationReceipt,
    body: RecoveryCheckpointBody,
) -> None:
    snapshot = body.legacy_snapshot
    if (
        body.holds
        or not body.prior_effects_reconciled
        or snapshot.validator_hotkey != receipt.validator_hotkey
        or snapshot.accepted_sequence != receipt.legacy_predecessor_sequence
        or snapshot.accepted_directive_sha256 != receipt.legacy_predecessor_directive_sha256
        or snapshot.accepted_at_finalized_block
        != receipt.legacy_predecessor_accepted_at_finalized_block
        or snapshot.config_sha256 != receipt.source_config_sha256
        or snapshot.installation_sha256 != receipt.legacy_installation_sha256
        or body.finalized_block != receipt.checkpoint_finalized_block
        or body.finalized_block_hash != receipt.checkpoint_finalized_block_hash
        or body.genesis_hash != receipt.checkpoint_genesis_hash
        or body.chain_config_sha256 != receipt.checkpoint_chain_config_sha256
    ):
        raise HostActivationError("retained recovery archive differs from installation receipt")


def _read_bound_controls(
    root_fd: int,
    receipt: SuccessorInstallationReceipt,
    *,
    owner: int,
) -> dict[str, bytes]:
    bindings = {
        SOURCE_CONFIG_FILENAME: (
            receipt.source_config_size_bytes,
            receipt.source_config_sha256,
        ),
        OPERATOR_CONSENT_FILENAME: (
            receipt.operator_consent_size_bytes,
            None,
        ),
        LEGACY_SIGNED_DIRECTIVE_FILENAME: (
            receipt.legacy_predecessor_signed_directive_size_bytes,
            receipt.legacy_predecessor_signed_directive_sha256,
        ),
        SIGNED_HOST_ARTIFACT_FILENAME: (
            receipt.signed_host_artifact_size_bytes,
            receipt.signed_host_artifact_sha256,
        ),
        WORKER_LIMITS_FILENAME: (
            receipt.worker_limits_size_bytes,
            receipt.worker_limits_sha256,
        ),
        HOST_OBSERVER_FILENAME: (
            receipt.host_observer_config_size_bytes,
            receipt.host_observer_config_sha256,
        ),
        INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME: (
            receipt.initial_successor_page_size_bytes,
            receipt.initial_successor_page_sha256,
        ),
    }
    result = {}
    for name, (size_or_limit, expected_sha256) in bindings.items():
        exact_size = expected_sha256 is not None or name == OPERATOR_CONSENT_FILENAME
        payload = _read_control_at(
            root_fd,
            name,
            size_or_limit,
            owner=owner,
            expected_size=size_or_limit if exact_size else None,
        )
        if expected_sha256 is not None and hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise HostActivationError("mounted control file differs from installation receipt")
        result[name] = payload
    if (
        successor_operator_consent_sha256(
            parse_canonical_successor_operator_consent(result[OPERATOR_CONSENT_FILENAME])
        )
        != receipt.operator_consent_sha256
    ):
        raise HostActivationError("mounted operator consent differs from installation receipt")
    return result


def _read_current_controls(root_fd: int, *, owner: int) -> dict[str, bytes]:
    limits = {
        CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME: MAX_SUCCESSOR_HISTORY_BYTES,
        RELEASE_IDENTITY_FILENAME: MAX_SUCCESSOR_RELEASE_IDENTITY_BYTES,
        WORKER_EXECUTION_FILENAME: MAX_SUCCESSOR_WORKER_EXECUTION_BYTES,
    }
    return {
        name: _read_control_at(root_fd, name, maximum, owner=owner)
        for name, maximum in limits.items()
    }


def _parse_and_verify_host_artifact(
    payload: bytes,
    *,
    config: ValidatorSupervisorConfig,
    expected_manifest_sha256: str,
):
    from .competition_host_artifacts import (
        parse_signed_host_artifact,
        verify_host_artifact_authority,
    )

    try:
        signed = parse_signed_host_artifact(payload)
        verify_host_artifact_authority(
            signed,
            config=config,
            expected_manifest_sha256=expected_manifest_sha256,
        )
    except (TypeError, ValueError) as error:
        raise HostActivationError("successor host artifact is not authenticated") from error
    return signed


def _parse_host_observer_config(payload: bytes) -> SuccessorHostObserverConfig:
    try:
        from .competition_supervisor_observer import (
            MAX_HOST_OBSERVER_CONFIG_BYTES,
            parse_successor_host_observer_config,
        )
    except ImportError:
        raise HostActivationError("successor host observer parser is unavailable") from None
    if MAX_HOST_OBSERVER_CONFIG_BYTES != MAX_SUCCESSOR_HOST_OBSERVER_CONFIG_BYTES:
        raise HostActivationError("successor host observer byte bounds disagree")
    try:
        return parse_successor_host_observer_config(payload)
    except (TypeError, ValueError) as error:
        raise HostActivationError("successor host observer config is invalid") from error


def _verify_host_observer_config(
    observer: SuccessorHostObserverConfig,
    *,
    config: ValidatorSupervisorConfig,
    checkpoint_genesis_hash: str,
) -> None:
    target = {
        "linux/amd64": "x86_64-unknown-linux-gnu",
        "linux/arm64": "aarch64-unknown-linux-gnu",
    }[config.target_platform]
    if (
        observer.policy.network != config.network
        or observer.policy.netuid != config.netuid
        or observer.chain.network != config.network
        or observer.chain.netuid != config.netuid
        or observer.chain.target_triple != target
        or "0x" + observer.chain.chain_pin.genesis_block_hash != checkpoint_genesis_hash
        or "0x" + observer.chain.finality_pin.expected_genesis_hash != checkpoint_genesis_hash
    ):
        raise HostActivationError(
            "successor host observer differs from the installed chain or platform"
        )


def _parse_worker_execution_config(payload: bytes) -> Any:
    _parse_canonical_json(
        payload,
        maximum_bytes=MAX_SUCCESSOR_WORKER_EXECUTION_BYTES,
        label="successor worker execution config",
    )
    try:
        from .competition_worker_cli import SuccessorWorkerExecutionConfig
    except ImportError:
        # The contract module can be installed before the fixed CLI module, but
        # it cannot seal or load worker inputs until that parser is available.
        raise HostActivationError("successor worker execution parser is unavailable") from None
    try:
        value = SuccessorWorkerExecutionConfig.model_validate_json(payload, strict=True)
    except Exception as error:
        raise HostActivationError("successor worker execution config is invalid") from error
    if canonical_json_bytes(value) != payload:
        raise HostActivationError("successor worker execution config is not canonical")
    return value


def _parse_worker_execution_limits(payload: bytes) -> SuccessorWorkerExecutionLimits:
    _parse_canonical_json(
        payload,
        maximum_bytes=MAX_SUCCESSOR_WORKER_LIMITS_BYTES,
        label="successor worker execution limits",
    )
    try:
        value = SuccessorWorkerExecutionLimits.model_validate_json(payload, strict=True)
    except Exception as error:
        raise HostActivationError("successor worker execution limits are invalid") from error
    if canonical_json_bytes(value) != payload:
        raise HostActivationError("successor worker execution limits are not canonical")
    return value


def _validate_worker_execution_bindings(
    execution: Any,
    *,
    directive: SuccessorSupervisorDirective,
    release_identity: CompetitionReleaseIdentity,
    authorization_body: Any | None,
    limits: SuccessorWorkerExecutionLimits,
) -> None:
    weights = execution.weights
    capacity = execution.replay_capacity
    ceiling = limits.replay_capacity_ceiling
    if (
        capacity.maximum_receipts > ceiling.maximum_receipts
        or capacity.maximum_bytes > ceiling.maximum_bytes
        or capacity.publication_journal.maximum_certificates
        > ceiling.publication_journal.maximum_certificates
        or capacity.publication_journal.maximum_bytes > ceiling.publication_journal.maximum_bytes
    ):
        raise HostActivationError("worker execution config exceeds installed ceilings")
    if (weights is not None) != (directive.mode == "competition_weights"):
        raise HostActivationError("worker execution config expands the selected profile")
    if weights is None:
        return
    if weights.evidence_storage != limits.weight_evidence_storage:
        raise HostActivationError("worker evidence storage differs from sealed installation")
    if (
        weights.maximum_attempts > limits.maximum_weight_attempts
        or weights.maximum_evidence_bytes > limits.maximum_weight_evidence_bytes
        or weights.submission_timeout_seconds > limits.maximum_submission_timeout_seconds
    ):
        raise HostActivationError("worker weight config exceeds installed ceilings")
    chain = weights.chain
    target = release_identity.target_triple
    if authorization_body is None or (
        chain.policy_sha256 != directive.policy_sha256
        or chain.network != directive.network
        or chain.netuid != directive.netuid
        or chain.chain_pin != directive.chain.chain_pin
        or chain.target_triple != target
        or authorization_body.required_finality_verifier_sha256_by_target.get(target)
        != chain.finality_pin.release_sha256_by_target.get(target)
        or authorization_body.required_storage_proof_verifier_sha256_by_target.get(target)
        != chain.proof_binary_sha256
    ):
        raise HostActivationError("worker chain config differs from signed successor authority")
    try:
        validate_runtime_execution_authorization(chain, authorization_body)
    except ValueError as error:
        raise HostActivationError(
            "worker runtime execution differs from signed authority"
        ) from error


def _parse_release_identity(payload: bytes) -> CompetitionReleaseIdentity:
    _parse_canonical_json(
        payload,
        maximum_bytes=MAX_SUCCESSOR_RELEASE_IDENTITY_BYTES,
        label="successor release identity",
    )
    try:
        value = CompetitionReleaseIdentity.model_validate_json(payload, strict=True)
    except Exception as error:
        raise HostActivationError("successor release identity is invalid") from error
    if canonical_json_bytes(value) != payload:
        raise HostActivationError("successor release identity is not canonical")
    return value


def _installation_binding(inputs: AuthenticatedSuccessorWorkerInputs) -> str:
    values = {
        "validator_hotkey": account_id32(inputs.validator_hotkey).hex(),
        "config_sha256": inputs.config_sha256,
        "authority_hotkeys": [account_id32(item).hex() for item in inputs.authority_hotkeys],
        "observed_config_sha256": successor_source_config_sha256(inputs.config),
        "consent_sha256": successor_operator_consent_sha256(inputs.operator_consent),
        "v3_state_sha256": hashlib.sha256(canonical_json_bytes(inputs.v3_state)).hexdigest(),
        "v3_signed_sha256": hashlib.sha256(inputs.v3_signed_bytes).hexdigest(),
        "initial_page_sha256": hashlib.sha256(
            canonical_json_bytes(inputs.initial_page)
        ).hexdigest(),
        "worker_limits_sha256": hashlib.sha256(
            canonical_json_bytes(inputs.worker_execution_limits)
        ).hexdigest(),
        "host_observer_config_sha256": hashlib.sha256(
            canonical_json_bytes(inputs.observer_config)
        ).hexdigest(),
        "checkpoint_sha256": inputs.checkpoint_sha256,
        "checkpoint_finalized_block": inputs.checkpoint_finalized_block,
        "initial_accepted_at_finalized_block": inputs.initial_accepted_at_finalized_block,
        "receipt_sha256": inputs.receipt_sha256,
        "receipt_body_sha256": hashlib.sha256(canonical_json_bytes(inputs._receipt)).hexdigest(),
        "host_manifest_sha256": inputs.host_manifest_sha256,
        "recovery_body_sha256": inputs._recovery_body_sha256,
        "recovery_predecessor_sha256": inputs._recovery_predecessor_sha256,
        "mount_root": str(inputs._mount.root),
        "anchor_owner_uid": inputs._mount.anchor_owner_uid,
        "anchor_control_sha256": inputs._mount.anchor_sha256,
        "anchor_snapshot_sha256": _tree_snapshot_sha256(
            tuple(item for item in inputs._mount.tree_snapshot if not item[0].startswith("current"))
        ),
    }
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()


def _worker_inputs_binding(inputs: AuthenticatedSuccessorWorkerInputs) -> str:
    values = {
        "installation": inputs._installation_binding,
        "profile": inputs.profile,
        "directive_sha256": inputs.directive_sha256,
        "signed_directive_sha256": hashlib.sha256(
            canonical_json_bytes(inputs.signed_directive)
        ).hexdigest(),
        "package_sha256": inputs.package_sha256,
        "package_body_sha256": inputs._package_body_sha256,
        "current_owner_uid": inputs._mount.current_owner_uid,
        "current_control_sha256": inputs._mount.current_sha256,
        "tree_snapshot_sha256": _tree_snapshot_sha256(inputs._mount.tree_snapshot),
        "authorization_sha256": inputs.authorization_sha256,
        "authorization_body_sha256": (
            None
            if inputs.authorization is None
            else hashlib.sha256(canonical_json_bytes(inputs.authorization)).hexdigest()
        ),
        "release_identity_sha256": hashlib.sha256(
            canonical_json_bytes(inputs.release_identity)
        ).hexdigest(),
        "current_page_sha256": hashlib.sha256(
            canonical_json_bytes(inputs.current_page)
        ).hexdigest(),
        "accepted_state_sha256": hashlib.sha256(
            canonical_json_bytes(inputs.accepted_state)
        ).hexdigest(),
        "worker_execution_sha256": hashlib.sha256(
            canonical_json_bytes(inputs.worker_execution_config)
        ).hexdigest(),
    }
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()


def _activation_binding(activation: AuthenticatedSuccessorActivation) -> str:
    values = {
        "inputs": activation._inputs._binding,
        "profile": activation.profile,
        "validator_hotkey": account_id32(activation.validator_hotkey).hex(),
        "config_sha256": activation.config_sha256,
        "directive_sha256": activation.directive_sha256,
        "package_sha256": activation.package_sha256,
        "authorization_sha256": activation.authorization_sha256,
        "release_identity_sha256": hashlib.sha256(
            canonical_json_bytes(activation.release_identity)
        ).hexdigest(),
        "authority_hotkeys": [account_id32(item).hex() for item in activation.authority_hotkeys],
        "checkpoint_sha256": activation.checkpoint_sha256,
        "accepted_state_sha256": hashlib.sha256(
            canonical_json_bytes(activation.accepted_state)
        ).hexdigest(),
        "signed_directive_sha256": hashlib.sha256(
            canonical_json_bytes(activation.signed_directive)
        ).hexdigest(),
        "finalized_block": activation.finalized_block,
        "finalized_block_hash": activation.finalized_block_hash,
        "owned_observation_identity": str(id(activation._observation)),
    }
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()


def _write_root_receipt_once(path: Path, payload: bytes) -> None:
    target = _canonical_absolute_path(path, "installation receipt")
    if target.name != INSTALLATION_RECEIPT_FILENAME:
        raise HostActivationError("installation receipt has the wrong fixed filename")
    parent = _open_absolute_directory(target.parent)
    try:
        publish_installation_receipt(
            parent,
            target.name,
            payload,
            owner=_root_owner_uid(),
            maximum_bytes=MAX_SUCCESSOR_INSTALLATION_RECEIPT_BYTES,
        )
    except (ValueError, OSError) as error:
        raise HostActivationError(str(error)) from error
    finally:
        os.close(parent)


def _read_root_control_path(
    path: Path,
    maximum_bytes: int,
    *,
    modes: set[int],
) -> bytes:
    target = _canonical_absolute_path(path, "root control file")
    parent = _open_absolute_directory(target.parent)
    try:
        return _read_regular_at(
            parent,
            target.name,
            maximum_bytes,
            owner=_root_owner_uid(),
            modes=modes,
        )
    finally:
        os.close(parent)


def _read_root_control_at(
    root_fd: int,
    name: str,
    maximum_bytes: int,
    *,
    expected_size: int | None = None,
) -> bytes:
    return _read_control_at(
        root_fd,
        name,
        maximum_bytes,
        owner=_root_owner_uid(),
        expected_size=expected_size,
    )


def _read_control_at(
    root_fd: int,
    name: str,
    maximum_bytes: int,
    *,
    owner: int,
    expected_size: int | None = None,
) -> bytes:
    return _read_regular_at(
        root_fd,
        name,
        maximum_bytes,
        owner=owner,
        modes={0o400, 0o440, 0o444},
        expected_size=expected_size,
    )


def _read_mounted_control_file(path: Path, expected_size: int, *, owner: int) -> bytes:
    target = _canonical_absolute_path(path, "mounted control")
    parent = _open_absolute_directory(target.parent)
    try:
        return _read_regular_at(
            parent,
            target.name,
            expected_size,
            owner=owner,
            modes={0o400, 0o440, 0o444},
            expected_size=expected_size,
        )
    finally:
        os.close(parent)


def _open_child_directory_at(parent: int, name: str) -> int:
    if "/" in name or name in {"", ".", ".."}:
        raise HostActivationError("activation directory name is invalid")
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
    except OSError as error:
        raise HostActivationError("could not open successor mount directory") from error


def _read_regular_at(
    directory: int,
    name: str,
    maximum_bytes: int,
    *,
    owner: int,
    modes: set[int],
    expected_size: int | None = None,
) -> bytes:
    if "/" in name or name in {"", ".", ".."}:
        raise HostActivationError("control filename is invalid")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=directory,
        )
    except OSError as error:
        raise HostActivationError("could not open successor control file") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in modes
            or before.st_size <= 0
            or before.st_size > maximum_bytes
            or (expected_size is not None and before.st_size != expected_size)
        ):
            raise HostActivationError("successor control file is unsafe or oversized")
        body = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise HostActivationError("successor control file was truncated")
            body.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise HostActivationError("successor control file grew while reading")
        after = os.fstat(descriptor)
        if _fingerprint(before) != _fingerprint(after):
            raise HostActivationError("successor control file changed while reading")
        return bytes(body)
    finally:
        os.close(descriptor)


def _top_entries(descriptor: int) -> set[str]:
    observed = set()
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if entry.name in observed or entry.is_symlink():
                raise HostActivationError("successor activation mount contains a link")
            if not entry.is_file(follow_symlinks=False) and not entry.is_dir(follow_symlinks=False):
                raise HostActivationError("successor activation mount entry is not regular")
            observed.add(entry.name)
            if len(observed) > len(_ANCHOR_CONTROL_FILENAMES) + 1:
                raise HostActivationError("successor activation mount has too many entries")
    return observed


def _open_absolute_directory(path: Path) -> int:
    target = _canonical_absolute_path(path, "directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for part in target.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _canonical_absolute_path(path: Path, label: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{label} path must be a Path")
    if not path.is_absolute() or path != Path(os.path.normpath(path)) or "\x00" in str(path):
        raise HostActivationError(f"{label} path must be canonical and absolute")
    return path


def _tree_snapshot_sha256(snapshot: tuple[tuple[str, tuple[int, ...]], ...]) -> str:
    # Filesystem nanoseconds and inode IDs need not fit the canonical JSON
    # integer domain. This private Python tuple never crosses a wire boundary.
    return hashlib.sha256(repr(snapshot).encode("utf-8")).hexdigest()


def _snapshot_mounted_tree(
    root: Path,
    limits: RecoveryLimits,
    *,
    stable_installation_only: bool = False,
) -> tuple[tuple[str, tuple[int, ...]], ...]:
    """Bounded metadata-only recheck of the already content-verified RO tree.

    The loader brackets full hash/signature/package verification with these
    snapshots. Later checks can therefore avoid replaying immutable evidence
    inside a fresh chain observation's lifetime. No snapshot loaded from JSON
    or supplied by a caller can mint an input capability.
    """
    rows: list[tuple[str, tuple[int, ...]]] = []
    maximum_entries = limits.maximum_files + limits.maximum_directories + 32
    maximum_depth = limits.maximum_depth + 4
    root_fd = _open_absolute_directory(root)

    def walk(descriptor: int, prefix: str, owner: int, depth: int) -> None:
        if depth > maximum_depth:
            raise HostActivationError("successor activation tree exceeds depth bound")
        before = os.fstat(descriptor)
        if before.st_uid != owner or stat.S_IMODE(before.st_mode) not in {0o500, 0o555}:
            raise HostActivationError("successor activation directory owner or mode is unsafe")
        _require_readonly_filesystem(root / prefix)
        rows.append((prefix, _fingerprint(before)))
        if len(rows) > maximum_entries:
            raise HostActivationError("successor activation tree exceeds entry bound")
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(rows) >= maximum_entries:
                    raise HostActivationError("successor activation tree exceeds entry bound")
                info = entry.stat(follow_symlinks=False)
                relative = prefix + "/" + entry.name
                if stat.S_ISDIR(info.st_mode):
                    child = _open_child_directory_at(descriptor, entry.name)
                    try:
                        if _fingerprint(os.fstat(child)) != _fingerprint(info):
                            raise HostActivationError("successor activation directory changed")
                        walk(child, relative, owner, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    child = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        dir_fd=descriptor,
                    )
                    try:
                        actual = os.fstat(child)
                        if (
                            _fingerprint(actual) != _fingerprint(info)
                            or actual.st_uid != owner
                            or actual.st_nlink != 1
                            or stat.S_IMODE(actual.st_mode) not in {0o400, 0o440, 0o444}
                        ):
                            raise HostActivationError(
                                "successor activation file identity is unsafe"
                            )
                        rows.append((relative, _fingerprint(actual)))
                    finally:
                        os.close(child)
                else:
                    raise HostActivationError(
                        "successor activation tree contains a link or special file"
                    )
        if _fingerprint(os.fstat(descriptor)) != _fingerprint(before):
            raise HostActivationError("successor activation directory changed during snapshot")

    try:
        _require_readonly_filesystem(root)
        info = os.fstat(root_fd)
        if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) != 0o555:
            raise HostActivationError("successor activation mount root is not immutable")
        if _top_entries(root_fd) != {ANCHOR_DIRECTORY_NAME, CURRENT_DIRECTORY_NAME}:
            raise HostActivationError("successor activation mount entries changed")
        # The service exchanges current below this same parent inode. Its
        # timestamps/size may change, but owner/mode/identity must not.
        rows.append(("", _fingerprint(info)[:6]))
        names = (
            (ANCHOR_DIRECTORY_NAME,)
            if stable_installation_only
            else (ANCHOR_DIRECTORY_NAME, CURRENT_DIRECTORY_NAME)
        )
        for name in names:
            child = _open_child_directory_at(root_fd, name)
            try:
                owner = os.fstat(child).st_uid
                if (
                    (name == ANCHOR_DIRECTORY_NAME and not _valid_anchor_mount_owner(owner))
                    or (name == CURRENT_DIRECTORY_NAME and owner != os.geteuid())
                    or stat.S_IMODE(os.fstat(child).st_mode) != 0o555
                ):
                    raise HostActivationError(
                        "successor activation subtree owner or mode is unsafe"
                    )
                walk(child, name, owner, 1)
            finally:
                os.close(child)
        if _fingerprint(os.fstat(root_fd))[:6] != rows[0][1]:
            raise HostActivationError("successor activation mount root changed")
        return tuple(sorted(rows))
    except OSError as error:
        raise HostActivationError("could not snapshot successor activation tree") from error
    finally:
        os.close(root_fd)


def _require_readonly_filesystem(path: Path) -> None:
    try:
        readonly = bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    except (AttributeError, OSError) as error:
        raise HostActivationError("could not verify successor read-only mount") from error
    if not readonly:
        raise HostActivationError("successor activation inputs are not on a read-only mount")


def _root_owner_uid() -> int:
    return 0


def _valid_anchor_mount_owner(owner: int) -> bool:
    # Rootful mounts retain uid 0. A root-owned file outside a rootless user
    # namespace is projected as Linux's fixed overflow uid. The host mount
    # adapter separately proves the source really is owned by host root.
    return owner in {0, 65_534} and (owner == 0 or owner != os.geteuid())


def _require_root_linux() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise HostActivationError("successor installation sealing requires root on Linux")


def _control_limit(name: str) -> int:
    return {
        INSTALLATION_RECEIPT_FILENAME: MAX_SUCCESSOR_INSTALLATION_RECEIPT_BYTES,
        SOURCE_CONFIG_FILENAME: MAX_SUPERVISOR_DOCUMENT_BYTES,
        OPERATOR_CONSENT_FILENAME: MAX_SUCCESSOR_DOCUMENT_BYTES,
        LEGACY_SIGNED_DIRECTIVE_FILENAME: MAX_SUPERVISOR_DOCUMENT_BYTES,
        INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME: MAX_SUCCESSOR_HISTORY_BYTES,
        CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME: MAX_SUCCESSOR_HISTORY_BYTES,
        SIGNED_HOST_ARTIFACT_FILENAME: 32 * 1024**2,
        RELEASE_IDENTITY_FILENAME: MAX_SUCCESSOR_RELEASE_IDENTITY_BYTES,
        WORKER_EXECUTION_FILENAME: MAX_SUCCESSOR_WORKER_EXECUTION_BYTES,
        WORKER_LIMITS_FILENAME: MAX_SUCCESSOR_WORKER_LIMITS_BYTES,
        HOST_OBSERVER_FILENAME: MAX_SUCCESSOR_HOST_OBSERVER_CONFIG_BYTES,
        WEIGHT_AUTHORIZATION_FILENAME: 4 * 1024**2,
    }[name]


def _canonical(model_type: type[_ModelT], value: _ModelT) -> _ModelT:
    return model_type.model_validate_json(canonical_json_bytes(value), strict=True)


def _parse_canonical_json(payload: bytes, *, maximum_bytes: int, label: str) -> Any:
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload or len(payload) > maximum_bytes:
        raise HostActivationError(f"{label} is missing or oversized")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
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
        raise HostActivationError(f"{label} is invalid JSON") from error
    if canonical_json_bytes(value) != payload:
        raise HostActivationError(f"{label} is not canonical")
    return value


__all__ = [
    "ACTIVATION_MOUNT_ROOT",
    "ANCHOR_DIRECTORY_NAME",
    "CURRENT_DIRECTORY_NAME",
    "CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME",
    "HOST_OBSERVER_FILENAME",
    "INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME",
    "INSTALLATION_RECEIPT_FILENAME",
    "LEGACY_SIGNED_DIRECTIVE_FILENAME",
    "MAX_SUCCESSOR_HOST_OBSERVER_CONFIG_BYTES",
    "MAX_SUCCESSOR_INSTALLATION_RECEIPT_BYTES",
    "OPERATOR_CONSENT_FILENAME",
    "PACKAGE_DIRECTORY_NAME",
    "RECOVERY_DIRECTORY_NAME",
    "RELEASE_IDENTITY_FILENAME",
    "SIGNED_HOST_ARTIFACT_FILENAME",
    "SOURCE_CONFIG_FILENAME",
    "SUCCESSOR_INSTALLATION_RECEIPT_DOMAIN",
    "SUCCESSOR_INSTALLATION_RECEIPT_SCHEMA",
    "WEIGHT_AUTHORIZATION_FILENAME",
    "WORKER_EXECUTION_FILENAME",
    "WORKER_LIMITS_FILENAME",
    "AuthenticatedSuccessorActivation",
    "AuthenticatedSuccessorWorkerInputs",
    "HostActivationError",
    "RetainedRecoveryReference",
    "SuccessorInstallationReceipt",
    "SuccessorWorkerExecutionLimits",
    "activate_successor_worker",
    "load_authenticated_successor_activation",
    "load_authenticated_successor_installation",
    "load_successor_worker_inputs",
    "parse_canonical_successor_installation_receipt",
    "seal_successor_installation_receipt",
    "successor_installation_receipt_sha256",
    "validate_authenticated_successor_activation",
    "validate_authenticated_successor_installation",
    "validate_authenticated_successor_worker_inputs",
]


def validate_evidence_migration_receipt(receipt, *, config, consent, worker_limits_bytes):
    """Validate both root records and the quorum-signed forward mapping.

    No source receipt, checkpoint, retained highwater or old limits are rewritten.
    The root seal records copy verification; it does not certify chain effects.
    """
    migration = receipt.evidence_migration
    if (migration is None) != (consent.history_compatibility is None):
        raise HostActivationError("history consent requires its root-sealed migration receipt")
    if migration is None:
        return
    body = verify_history_compatibility(consent.history_compatibility, config=config)
    validate_consent_transition(consent, consent.historical_consent, body)
    if (
        receipt.operator_consent_sha256 != successor_operator_consent_sha256(consent)
        or receipt.operator_consent_size_bytes != len(canonical_json_bytes(consent))
        or receipt.worker_limits_size_bytes != len(worker_limits_bytes)
    ):
        raise HostActivationError("migration root controls differ from the selected consent/limits")
    original_bytes = bytes.fromhex(migration.original_receipt_hex)
    original = parse_canonical_successor_installation_receipt(original_bytes)
    original_limits_bytes = bytes.fromhex(migration.original_worker_limits_hex)
    old_limits = _parse_worker_execution_limits(original_limits_bytes)
    new_limits = _parse_worker_execution_limits(worker_limits_bytes)
    if original.evidence_migration is not None or old_limits.weight_evidence_storage is not None:
        raise HostActivationError("only one explicit legacy-to-CAS transition is supported")
    storage = new_limits.weight_evidence_storage
    if storage is None:
        raise HostActivationError("migration target lacks evidence storage profile")
    identities = (
        (hashlib.sha256(original_bytes).hexdigest(), body.original_installation_receipt_sha256),
        (
            hashlib.sha256(canonical_json_bytes(consent.history_compatibility)).hexdigest(),
            migration.compatibility_sha256,
        ),
        (original.operator_consent_sha256, body.original_consent_sha256),
        (original_consent_digest(consent.historical_consent), body.original_consent_sha256),
        (original.host_manifest_sha256, body.original_host_manifest_sha256),
        (receipt.host_manifest_sha256, body.target_host_manifest_sha256),
        (original.worker_limits_sha256, body.original_worker_limits_sha256),
        (hashlib.sha256(original_limits_bytes).hexdigest(), body.original_worker_limits_sha256),
        (receipt.worker_limits_sha256, body.target_worker_limits_sha256),
        (hashlib.sha256(worker_limits_bytes).hexdigest(), body.target_worker_limits_sha256),
        (
            hashlib.sha256(canonical_json_bytes(storage)).hexdigest(),
            body.target_storage_config_sha256,
        ),
        (original.checkpoint_sha256, body.original_checkpoint_sha256),
        (migration.retained_history_sha256, body.retained_history_sha256),
        (
            hashlib.sha256(bytes.fromhex(migration.predecessor_state_hex)).hexdigest(),
            body.predecessor_state_sha256,
        ),
    )
    if any(a != b for a, b in identities):
        raise HostActivationError("migration receipt differs from signed compatibility")
    # Only these fields may differ in the new root-owned receipt. All original
    # observer/chain/checkpoint/v3/initial-history fields must be byte-identical.
    changed = {
        "schema",
        "evidence_migration",
        "operator_consent_sha256",
        "operator_consent_size_bytes",
        "signed_host_artifact_sha256",
        "signed_host_artifact_size_bytes",
        "host_manifest_sha256",
        "host_umi_git_revision",
        "worker_limits_sha256",
        "worker_limits_size_bytes",
    }
    old_values, new_values = original.model_dump(by_alias=True), receipt.model_dump(by_alias=True)
    if {k: v for k, v in old_values.items() if k not in changed} != {
        k: v for k, v in new_values.items() if k not in changed
    }:
        raise HostActivationError("migration rewrites original installation history")
    if (
        new_limits.maximum_weight_attempts != old_limits.maximum_weight_attempts
        or new_limits.maximum_weight_evidence_bytes != old_limits.maximum_weight_evidence_bytes
        or not body.migration_valid_from_block
        <= migration.migration_finalized_block
        <= body.migration_valid_through_block
        or migration.migration_finalized_block < body.predecessor_accepted_at_finalized_block
    ):
        raise HostActivationError("migration changes legacy owner binding or has invalid block")
    prior_raw = bytes.fromhex(migration.predecessor_state_hex)
    prior = SuccessorSupervisorDirectiveState.model_validate_json(prior_raw, strict=True)
    if (
        canonical_json_bytes(prior) != prior_raw
        or prior.accepted_sequence != body.predecessor_sequence
        or prior.accepted_directive_sha256 != body.predecessor_directive_sha256
        or prior.accepted_at_finalized_block != body.predecessor_accepted_at_finalized_block
        or prior.operator_consent_sha256 != body.original_consent_sha256
        or prior.source_config_sha256 != body.source_config_sha256
    ):
        raise HostActivationError("migration predecessor state binding differs")
    preparation_raw = bytes.fromhex(migration.preparation_receipt_hex)
    preparation = json.loads(preparation_raw)
    if (
        canonical_json_bytes(preparation) != preparation_raw
        or preparation.get("schema") != "umi-weight-evidence-preparation/1"
    ):
        raise HostActivationError("migration preparation receipt is not canonical")
    expected = {
        "source_root": migration.source_root,
        "candidate_root": migration.candidate_root,
        "source_database_sha256": migration.source_database_sha256,
        "candidate_database_sha256": migration.candidate_database_sha256,
        "maximum_database_bytes": storage.maximum_database_bytes,
        "worker_profile_sha256": hashlib.sha256(storage.profile().encoded()).hexdigest(),
        "source_selection_changed": False,
        "activation_authorized": False,
        "root_sealed": False,
    }
    if any(preparation.get(k) != v for k, v in expected.items()):
        raise HostActivationError("migration preparation differs from selected profile or database")


def retained_execution_limits(installation, directive):
    """Old limits apply only to authenticated history, never new execution."""
    consent = installation.operator_consent
    selected = consent_for_retained_directive(
        consent, directive, config=installation.config, historical=True
    )
    if (
        selected.schema_ == "umi-validator-supervisor-operator-consent/1"
        and consent.history_compatibility is not None
    ):
        migration = installation._receipt.evidence_migration
        if migration is None:
            raise HostActivationError("retained history lacks root-sealed original limits")
        return _parse_worker_execution_limits(bytes.fromhex(migration.original_worker_limits_hex))
    return installation.worker_execution_limits


def selected_weight_state_root(installation):
    """Physical host store selected by the immutable installation receipt."""
    migration = installation._receipt.evidence_migration
    if migration is None:
        return Path(installation.config.worker_state_root) / "competition" / "weights"
    return Path(migration.candidate_root)
