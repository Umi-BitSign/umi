"""Read-only inspection of an installed supervisor before a successor upgrade.

This checks existing host contracts, not a proposed successor authorization.
It does not read a wallet, acquire a process lock, open SQLite, execute a release,
contact a service or write a checkpoint. Historical bytes are hashed as read.
The result cannot authorize stopping, upgrading or submitting weights.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .crypto import verify_response_signature
from .encoding import account_id32
from .protocol import canonical_json_bytes
from .registration_bridge import registration_bridge_policy_sha256
from .validator_supervisor import (
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES,
    SignedSupervisorDirective,
    ValidatorSupervisorConfig,
    ValidatorSupervisorError,
    advance_supervisor_directive_history_state,
    parse_canonical_signed_supervisor_directive,
    parse_canonical_supervisor_directive_state,
    parse_canonical_validator_supervisor_config,
)
from .validator_supervisor_adapters import (
    MAX_RELEASE_MANIFEST_BYTES,
    SUPERVISOR_RELEASE_BUNDLE_MAGIC,
    SUPERVISOR_RELEASE_SIGNATURE_DOMAIN,
    SupervisorRegistrationBridgeInputBundle,
    SupervisorSimpleBootstrapInputBundle,
    ValidatorSupervisorAdapterError,
    _parse_bootstrap_input_bundle,
    _parse_release_manifest,
    _verify_manifest_binding,
)
from .validator_supervisor_runtime import DIRECTIVE_STATE_FILENAME

_REMAINING_HOLDS = (
    "successor_host_contract_not_implemented",
    "replacement_host_source_not_authenticated",
    "operator_upgrade_consent_required",
    "actual_host_platform_and_dependencies_not_checked",
    "production_sandbox_not_rehearsed",
    "service_stop_and_empty_cgroup_not_verified",
    "consistent_stopped_checkpoint_required",
    "worker_journals_not_reconciled",
    "hotkey_possession_not_checked",
    "fresh_finality_and_policy_validity_not_checked",
    "successor_chain_authorization_not_verified",
)


class UpgradeInspectionError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class FileObservation:
    """Exact bytes observed, with a non-sensitive logical name instead of a path."""

    label: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class UpgradeInspection:
    verified_checks: tuple[str, ...]
    holds: tuple[str, ...]
    files: tuple[FileObservation, ...]
    validator_account_id32: str | None = None
    target_platform: str | None = None
    wallet_binding_sha256: str | None = None
    accepted_sequence: int | None = None
    accepted_directive_sha256: str | None = None
    accepted_at_finalized_block: int | None = None
    staged_directive_sha256: str | None = None
    observed_files_unchanged: bool = False
    schema: Literal["umi-successor-host-upgrade-inspection/1"] = field(
        default="umi-successor-host-upgrade-inspection/1", init=False
    )
    readiness: Literal["hold"] = field(default="hold", init=False)
    may_stop_service: Literal[False] = field(default=False, init=False)
    host_upgrade_authorized: Literal[False] = field(default=False, init=False)
    chain_submission_authorized: Literal[False] = field(default=False, init=False)
    consistent_stopped_checkpoint: Literal[False] = field(default=False, init=False)


def _fingerprint(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
        details.st_gid,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _open_without_links(path: Path) -> int:
    """Use directory descriptors so no intermediate or final symlink is followed."""
    if not path.is_absolute() or path != Path(os.path.normpath(path)) or path == Path("/"):
        raise UpgradeInspectionError("inspection_path_invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory = os.open("/", flags | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(path.name, flags, dir_fd=directory)
    finally:
        os.close(directory)


class _Reader:
    def __init__(self, service_uid: int):
        self.service_uid = service_uid
        self.observations: list[FileObservation] = []
        self.identities: dict[Path, tuple[int, ...]] = {}

    def _remember(self, path: Path, details: os.stat_result) -> None:
        identity = _fingerprint(details)
        prior = self.identities.get(path)
        if prior is not None and prior != identity:
            raise UpgradeInspectionError("inspection_files_changed")
        self.identities[path] = identity

    def directory(
        self, path: Path, *, modes: set[int] | frozenset[int] = frozenset({0o700, 0o500})
    ) -> None:
        descriptor = _open_without_links(path)
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != self.service_uid
                or stat.S_IMODE(details.st_mode) not in modes
            ):
                raise UpgradeInspectionError("inspection_directory_unsafe")
            self._remember(path, details)
        finally:
            os.close(descriptor)

    def file(
        self,
        path: Path,
        label: str,
        maximum: int,
        *,
        modes: set[int] | frozenset[int] = frozenset({0o400, 0o600}),
        root_owned: bool = False,
        expected_size: int | None = None,
        expected_sha256: str | None = None,
        retain: bool = True,
    ) -> bytes:
        descriptor = _open_without_links(path)
        try:
            before = os.fstat(descriptor)
            owners = {0, self.service_uid} if root_owned else {self.service_uid}
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid not in owners
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) not in modes
                or not 0 < before.st_size <= maximum
            ):
                raise UpgradeInspectionError(f"{label}_file_unsafe")
            content, hasher, total = bytearray(), hashlib.sha256(), 0
            while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - total)):
                total += len(chunk)
                if total > maximum:
                    raise UpgradeInspectionError(f"{label}_size_mismatch")
                hasher.update(chunk)
                if retain:
                    content.extend(chunk)
            after = os.fstat(descriptor)
            if _fingerprint(before) != _fingerprint(after) or total != before.st_size:
                raise UpgradeInspectionError("inspection_files_changed")
            observed_sha = hasher.hexdigest()
            if expected_size is not None and total != expected_size:
                raise UpgradeInspectionError(f"{label}_size_mismatch")
            if expected_sha256 is not None and observed_sha != expected_sha256:
                raise UpgradeInspectionError(f"{label}_sha256_mismatch")
            self._remember(path, after)
            self.observations.append(FileObservation(label, observed_sha, total))
            return bytes(content)
        finally:
            os.close(descriptor)

    def unchanged(self) -> None:
        for path, identity in self.identities.items():
            descriptor = _open_without_links(path)
            try:
                if _fingerprint(os.fstat(descriptor)) != identity:
                    raise UpgradeInspectionError("inspection_files_changed")
            finally:
                os.close(descriptor)


def _verify_release(reader: _Reader, root: Path, signed: SignedSupervisorDirective, label: str):
    """Check framed bundle and extracted files, without extracting or loading OCI."""
    directive = signed.directive
    target = directive.release
    if target is None:
        raise UpgradeInspectionError(f"{label}_release_target_missing")
    reader.directory(root)
    path = root / "release-bundle.bin"
    # Hash the bounded file first; parse only its small header on a second read.
    reader.file(
        path,
        f"{label}_bundle",
        target.release_bundle_size_bytes,
        modes={0o400},
        expected_size=target.release_bundle_size_bytes,
        expected_sha256=target.release_bundle_sha256,
        retain=False,
    )
    descriptor = _open_without_links(path)
    try:

        def read_exact(size: int) -> bytes:
            chunks = bytearray()
            while len(chunks) < size:
                chunk = os.read(descriptor, size - len(chunks))
                if not chunk:
                    raise UpgradeInspectionError(f"{label}_bundle_truncated")
                chunks.extend(chunk)
            return bytes(chunks)

        if read_exact(len(SUPERVISOR_RELEASE_BUNDLE_MAGIC)) != SUPERVISOR_RELEASE_BUNDLE_MAGIC:
            raise UpgradeInspectionError(f"{label}_bundle_magic_invalid")
        size = struct.unpack(">I", read_exact(4))[0]
        if not 0 < size <= MAX_RELEASE_MANIFEST_BYTES:
            raise UpgradeInspectionError(f"{label}_manifest_size_invalid")
        payload, signature = read_exact(size), read_exact(64)
        manifest = _parse_release_manifest(payload)
        _verify_manifest_binding(manifest, target)
        if hashlib.sha256(payload).hexdigest() != target.release_manifest_sha256:
            raise UpgradeInspectionError(f"{label}_manifest_sha256_mismatch")
        if not verify_response_signature(
            hashlib.sha256(SUPERVISOR_RELEASE_SIGNATURE_DOMAIN + payload).digest(),
            hotkey_ss58=target.release_authority_hotkey,
            scheme=target.release_authority_signature_scheme,
            signature="0x" + signature.hex(),
        ):
            raise UpgradeInspectionError(f"{label}_release_signature_invalid")
        archive_hash, total = hashlib.sha256(), 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > manifest.oci_archive_size_bytes:
                raise UpgradeInspectionError(f"{label}_archive_size_mismatch")
            archive_hash.update(chunk)
        if (
            total != manifest.oci_archive_size_bytes
            or archive_hash.hexdigest() != manifest.oci_archive_sha256
        ):
            raise UpgradeInspectionError(f"{label}_archive_binding_mismatch")
        reader._remember(path, os.fstat(descriptor))
    finally:
        os.close(descriptor)
    if (
        reader.file(
            root / "release-manifest.json",
            f"{label}_manifest",
            MAX_RELEASE_MANIFEST_BYTES,
            modes={0o400},
        )
        != payload
    ):
        raise UpgradeInspectionError(f"{label}_extracted_manifest_mismatch")
    reader.file(
        root / "image.oci.tar",
        f"{label}_archive",
        manifest.oci_archive_size_bytes,
        modes={0o400},
        expected_size=manifest.oci_archive_size_bytes,
        expected_sha256=manifest.oci_archive_sha256,
        retain=False,
    )
    if directive.operator_inputs is None:
        for name in ("operator-input-bundle.json", "operator-inputs"):
            try:
                (root / name).lstat()
            except FileNotFoundError:
                continue
            raise UpgradeInspectionError(f"{label}_unexpected_operator_inputs")
        return
    inputs = directive.operator_inputs
    encoded = reader.file(
        root / "operator-input-bundle.json",
        f"{label}_inputs",
        MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES,
        modes={0o400},
        expected_size=inputs.bundle_size_bytes,
        expected_sha256=inputs.bundle_sha256,
    )
    bundle = _parse_bootstrap_input_bundle(encoded)
    if bundle.profile != inputs.profile:
        raise UpgradeInspectionError(f"{label}_input_policy_binding_mismatch")
    if isinstance(bundle, SupervisorRegistrationBridgeInputBundle):
        if registration_bridge_policy_sha256(bundle.signed_policy) != directive.policy_sha256:
            raise UpgradeInspectionError(f"{label}_input_policy_binding_mismatch")
        if bundle.signed_policy.body.umi_git_revision != target.umi_git_revision:
            raise UpgradeInspectionError(f"{label}_input_release_binding_mismatch")
        content_name = "registration-bridge"
        expected = {"registration-bridge-policy.json": canonical_json_bytes(bundle.signed_policy)}
    else:
        if bundle.signed_manifest.manifest.policy_sha256 != directive.policy_sha256:
            raise UpgradeInspectionError(f"{label}_input_policy_binding_mismatch")
        content_name = "bootstrap"
        expected = {"signed-manifest.json": canonical_json_bytes(bundle.signed_manifest)}
        if isinstance(bundle, SupervisorSimpleBootstrapInputBundle):
            if bundle.signed_lease.body.umi_git_revision != target.umi_git_revision:
                raise UpgradeInspectionError(f"{label}_input_release_binding_mismatch")
            expected["bootstrap-lease.json"] = canonical_json_bytes(bundle.signed_lease)
        else:
            expected.update(
                {
                    "direct-transition-authorization.json": canonical_json_bytes(
                        bundle.transition_authorization
                    ),
                    "drain-checkpoint.json": canonical_json_bytes(bundle.drain_checkpoint),
                    "owner-fence-receipt.json": canonical_json_bytes(bundle.owner_fence_receipt),
                }
            )
    reader.directory(root / "operator-inputs", modes={0o500})
    content_root = root / "operator-inputs" / content_name
    _require_directory_names(root / "operator-inputs", {content_name}, label)
    reader.directory(content_root, modes={0o500})
    _require_directory_names(content_root, set(expected), label)
    for name, body in expected.items():
        if (
            reader.file(
                content_root / name,
                f"{label}_{name}",
                MAX_SUPERVISOR_DOCUMENT_BYTES,
                modes={0o400},
            )
            != body
        ):
            raise UpgradeInspectionError(f"{label}_extracted_input_mismatch")


def _require_directory_names(path: Path, expected: set[str], label: str) -> None:
    descriptor = _open_without_links(path)
    try:
        names = set()
        with os.scandir(descriptor) as entries:
            for entry in entries:
                names.add(entry.name)
                if len(names) > len(expected):
                    raise UpgradeInspectionError(f"{label}_input_file_set_mismatch")
        if names != expected:
            raise UpgradeInspectionError(f"{label}_input_file_set_mismatch")
    finally:
        os.close(descriptor)


def inspect_successor_upgrade(
    *,
    config_path: Path,
    accepted_directive_bytes: bytes,
    expected_hotkey: str,
    expected_platform: Literal["linux/amd64", "linux/arm64"],
    service_uid: int,
    staged_directory: Path | None = None,
) -> UpgradeInspection:
    """Inspect as the service user (or root), without stopping the installation.

    Supply the accepted signed directive from retained public evidence. The
    installed high-water record, not that supplied document, selects the head.
    An optional separate stage contains ``signed-directive.json`` and the normal
    extracted release files. Its directive must extend the accepted head by one
    under unchanged local trust. This does not accept or publish that directive.

    The accepted block is an unverified historical local value. This API has no
    live block argument that could be mistaken for an owned finality proof.
    Worker journals are deliberately not opened; a stopped-state checkpoint and
    version-aware effect reconciliation are still required by an actual upgrade.
    """
    if isinstance(service_uid, bool) or not isinstance(service_uid, int) or service_uid < 0:
        raise ValueError("service_uid must be a nonnegative integer")
    reader = _Reader(service_uid)
    verified: list[str] = []
    holds: list[str] = []
    fields: dict = {}
    try:
        config_bytes = reader.file(
            config_path,
            "config",
            MAX_SUPERVISOR_DOCUMENT_BYTES,
            modes={0o400, 0o440, 0o600, 0o640},
            root_owned=True,
        )
        config: ValidatorSupervisorConfig = parse_canonical_validator_supervisor_config(
            config_bytes
        )
        if account_id32(config.validator_hotkey) != account_id32(expected_hotkey):
            raise UpgradeInspectionError("installed_hotkey_binding_mismatch")
        if (
            expected_platform not in {"linux/amd64", "linux/arm64"}
            or config.target_platform != expected_platform
        ):
            raise UpgradeInspectionError("installed_platform_binding_mismatch")
        fields.update(
            validator_account_id32=account_id32(config.validator_hotkey).hex(),
            target_platform=config.target_platform,
            wallet_binding_sha256=hashlib.sha256(canonical_json_bytes(config.wallet)).hexdigest(),
        )
        verified.append("installed_config_and_expected_public_hotkey")
        for root in (
            config.state_root,
            config.worker_state_root,
            config.release_root,
            config.operator_input_root,
        ):
            reader.directory(Path(root), modes={0o700})
        verified.append("installed_non_wallet_root_permissions")
        state_bytes = reader.file(
            Path(config.state_root) / DIRECTIVE_STATE_FILENAME,
            "highwater",
            MAX_SUPERVISOR_DOCUMENT_BYTES,
            modes={0o600},
        )
        state = parse_canonical_supervisor_directive_state(
            state_bytes, trust_policy=config.trust_policy()
        )
        signed = parse_canonical_signed_supervisor_directive(accepted_directive_bytes)
        checked = advance_supervisor_directive_history_state(
            signed,
            config=config,
            finalized_block=state.accepted_at_finalized_block,
            prior_state=state,
        )
        if checked != state:
            raise UpgradeInspectionError("accepted_directive_does_not_match_highwater")
        reader.observations.append(
            FileObservation(
                "accepted_signed_directive",
                hashlib.sha256(accepted_directive_bytes).hexdigest(),
                len(accepted_directive_bytes),
            )
        )
        fields.update(
            accepted_sequence=state.accepted_sequence,
            accepted_directive_sha256=state.accepted_directive_sha256,
            accepted_at_finalized_block=state.accepted_at_finalized_block,
        )
        verified.append("accepted_signature_and_highwater_execution_binding")
        if signed.directive.release is not None:
            _verify_release(
                reader,
                Path(config.release_root) / state.accepted_directive_sha256,
                signed,
                "installed",
            )
            verified.append("installed_release_and_input_bytes")
        if staged_directory is None:
            holds.append("staged_release_not_supplied")
        else:
            # A stage must not overlay any existing state, release, input or wallet tree.
            for value in (
                config.state_root,
                config.worker_state_root,
                config.release_root,
                config.operator_input_root,
                config.wallet.path,
            ):
                root = Path(value)
                if (
                    staged_directory == root
                    or root in staged_directory.parents
                    or staged_directory in root.parents
                ):
                    raise UpgradeInspectionError("stage_overlaps_installed_roots")
            reader.directory(staged_directory)
            staged_bytes = reader.file(
                staged_directory / "signed-directive.json",
                "staged_directive",
                MAX_SUPERVISOR_DOCUMENT_BYTES,
            )
            staged = parse_canonical_signed_supervisor_directive(staged_bytes)
            if staged.directive.sequence != state.accepted_sequence + 1:
                raise UpgradeInspectionError("staged_directive_not_next_sequence")
            # Historical verification authenticates consent/bindings, not lease validity now.
            advance_supervisor_directive_history_state(
                staged,
                config=config,
                finalized_block=max(
                    state.accepted_at_finalized_block, staged.directive.issued_at_block
                ),
                prior_state=state,
            )
            _verify_release(reader, staged_directory, staged, "staged")
            fields["staged_directive_sha256"] = staged.directive_sha256
            verified.append("staged_signed_worker_release_under_installed_consent")
    except (
        ValueError,
        TypeError,
        OSError,
        ValidatorSupervisorError,
        ValidatorSupervisorAdapterError,
    ) as error:
        reason = getattr(error, "reason_code", "inspection_input_unavailable_or_invalid")
        holds.append(reason)
    try:
        reader.unchanged()
        fields["observed_files_unchanged"] = True
    except (ValueError, OSError):
        holds.append("inspection_files_changed")
    return UpgradeInspection(
        verified_checks=tuple(verified),
        holds=tuple(dict.fromkeys([*holds, *_REMAINING_HOLDS])),
        files=tuple(reader.observations),
        **fields,
    )
