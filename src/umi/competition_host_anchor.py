"""Materialize the immutable root-owned half of successor activation inputs.

This module copies only fixed authenticated controls and one verified recovery
archive. It does not write the rolling current tree, switch systemd, start a
worker, read a wallet or grant chain-submission authority.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import os
import secrets
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import competition_host_activation as activation
from .competition_recovery import (
    RecoveryCheckpointBody,
    RecoveryLimits,
    VerifiedRecoveryCheckpoint,
    load_installed_retained_checkpoint_archive,
    load_retained_checkpoint_archive,
    validate_checkpoint_for_successor,
)
from .competition_supervisor import (
    SuccessorSupervisorDirectivePage,
    SuccessorSupervisorDirectiveState,
    SuccessorSupervisorOperatorConsent,
    parse_canonical_successor_operator_consent,
    parse_canonical_successor_supervisor_directive_history,
    successor_source_config_sha256,
)
from .file_identity import file_fingerprint as _fingerprint
from .protocol import canonical_json_bytes
from .validator_supervisor import (
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    SignedSupervisorDirective,
    SupervisorDirectiveState,
    ValidatorSupervisorConfig,
    parse_canonical_signed_supervisor_directive,
    parse_canonical_validator_supervisor_config,
)

ACTIVATION_SOURCE_DIRECTORY_NAME = "activation-source"
ANCHOR_STAGING_PREFIX = ".anchor-partial-"
_ANCHOR_TOKEN = object()
_RENAME_NOREPLACE = 1

_SOURCE_CONTROLS = (
    (
        activation.SOURCE_CONFIG_FILENAME,
        "config_path",
        MAX_SUPERVISOR_DOCUMENT_BYTES,
        frozenset({0o400, 0o440, 0o444, 0o600, 0o640}),
    ),
    (
        activation.OPERATOR_CONSENT_FILENAME,
        "operator_consent_path",
        activation.MAX_SUCCESSOR_DOCUMENT_BYTES,
        frozenset({0o400, 0o440, 0o444}),
    ),
    (
        activation.LEGACY_SIGNED_DIRECTIVE_FILENAME,
        "legacy_signed_directive_path",
        MAX_SUPERVISOR_DOCUMENT_BYTES,
        frozenset({0o400, 0o440, 0o444}),
    ),
    (
        activation.INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
        "initial_successor_page_path",
        activation.MAX_SUCCESSOR_HISTORY_BYTES,
        frozenset({0o400, 0o440, 0o444}),
    ),
    (
        activation.SIGNED_HOST_ARTIFACT_FILENAME,
        "signed_host_artifact_path",
        32 * 1024**2,
        frozenset({0o400, 0o440, 0o444}),
    ),
    (
        activation.WORKER_LIMITS_FILENAME,
        "worker_limits_path",
        activation.MAX_SUCCESSOR_WORKER_LIMITS_BYTES,
        frozenset({0o400, 0o440, 0o444}),
    ),
    (
        activation.HOST_OBSERVER_FILENAME,
        "host_observer_config_path",
        activation.MAX_SUCCESSOR_HOST_OBSERVER_CONFIG_BYTES,
        frozenset({0o400, 0o440, 0o444}),
    ),
)
_ANCHOR_ENTRIES = frozenset(
    {
        activation.INSTALLATION_RECEIPT_FILENAME,
        activation.SOURCE_CONFIG_FILENAME,
        activation.OPERATOR_CONSENT_FILENAME,
        activation.LEGACY_SIGNED_DIRECTIVE_FILENAME,
        activation.INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
        activation.SIGNED_HOST_ARTIFACT_FILENAME,
        activation.WORKER_LIMITS_FILENAME,
        activation.HOST_OBSERVER_FILENAME,
        activation.RECOVERY_DIRECTORY_NAME,
    }
)


class SuccessorAnchorError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MaterializedSuccessorAnchor:
    """Non-authorizing integrity capability for one installed anchor."""

    source_root: Path
    config: ValidatorSupervisorConfig
    operator_consent: SuccessorSupervisorOperatorConsent
    worker_execution_limits: activation.SuccessorWorkerExecutionLimits
    observer_config: Any
    receipt: activation.SuccessorInstallationReceipt
    receipt_sha256: str
    v3_state: SupervisorDirectiveState
    v3_signed_bytes: bytes
    initial_page: SuccessorSupervisorDirectivePage
    initial_state: SuccessorSupervisorDirectiveState
    recovery: RecoveryCheckpointBody
    service_uid: int
    _source_parent_identity: tuple[int, ...] = field(repr=False, compare=False)
    _source_root_identity: tuple[int, ...] = field(repr=False, compare=False)
    _anchor_snapshot_sha256: str = field(repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    @property
    def anchor_path(self) -> Path:
        return self.source_root / activation.ANCHOR_DIRECTORY_NAME

    def recheck(self) -> None:
        validate_materialized_successor_anchor(self)

    def recheck_for_parent_repair(self) -> None:
        validate_materialized_successor_anchor_for_repair(self)


@dataclass(frozen=True, slots=True)
class _SourceFile:
    path: Path
    payload: bytes
    identity: tuple[int, ...]
    maximum_bytes: int
    modes: frozenset[int]


@dataclass(frozen=True, slots=True)
class _AnchorSnapshot:
    source_parent_identity: tuple[int, ...]
    source_root_identity: tuple[int, ...]
    service_uid: int
    snapshot_sha256: str
    config: ValidatorSupervisorConfig
    consent: SuccessorSupervisorOperatorConsent
    limits: activation.SuccessorWorkerExecutionLimits
    observer_config: Any
    receipt: activation.SuccessorInstallationReceipt
    v3_state: SupervisorDirectiveState
    v3_signed_bytes: bytes
    initial_page: SuccessorSupervisorDirectivePage
    initial_state: SuccessorSupervisorDirectiveState
    recovery: RecoveryCheckpointBody


def successor_activation_source_root(config: ValidatorSupervisorConfig) -> Path:
    config = ValidatorSupervisorConfig.model_validate_json(
        canonical_json_bytes(config), strict=True
    )
    state_root = _canonical_absolute(Path(config.state_root), "successor state root")
    return state_root / "successor-v4" / ACTIVATION_SOURCE_DIRECTORY_NAME


def materialize_successor_anchor(
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
) -> MaterializedSuccessorAnchor:
    """Install an anchor once while the stopped checkpoint remains live."""

    _require_root_linux()
    arguments = locals()
    sources: dict[str, _SourceFile] = {}
    for destination, argument, maximum, modes in _SOURCE_CONTROLS:
        path = arguments[argument]
        if destination != activation.SOURCE_CONFIG_FILENAME and path.name != destination:
            raise SuccessorAnchorError("successor control source has the wrong fixed filename")
        sources[destination] = _read_source(path, maximum_bytes=maximum, modes=modes)
    control_parents = {
        item.path.parent
        for name, item in sources.items()
        if name != activation.SOURCE_CONFIG_FILENAME
    }
    if len(control_parents) != 1:
        raise SuccessorAnchorError("successor controls must share one private staging parent")
    _require_private_control_parent(next(iter(control_parents)))

    config = parse_canonical_validator_supervisor_config(
        sources[activation.SOURCE_CONFIG_FILENAME].payload
    )
    source_root, service_uid, source_parent_identity, source_root_identity = (
        _validate_source_hierarchy(config, allow_parent_repair=False)
    )
    _validate_service_uid(service_uid)
    if verified_checkpoint._stopped.service_uid != service_uid:
        raise SuccessorAnchorError("recovery checkpoint belongs to another service account")
    consent = parse_canonical_successor_operator_consent(
        sources[activation.OPERATOR_CONSENT_FILENAME].payload
    )
    validate_checkpoint_for_successor(
        verified_checkpoint,
        validator_hotkey=config.validator_hotkey,
        predecessor_directive_sha256=consent.predecessor_directive_sha256,
        minimum_finalized_block=consent.predecessor_accepted_at_finalized_block,
    )
    source_recovery, source_objects = load_retained_checkpoint_archive(
        recovery_archive_path,
        expected_sha256=verified_checkpoint.checkpoint_sha256,
        owner=service_uid,
        limits=recovery_limits,
    )
    if source_recovery != verified_checkpoint._body:
        raise SuccessorAnchorError("recovery source differs from its verified capability")

    parent = _open_directory(source_root)
    stage_name = ANCHOR_STAGING_PREFIX + secrets.token_hex(16)
    stage_fd = -1
    try:
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked_info = _require_directory(parent, owner=service_uid, modes={0o555})
        if _stable_directory_identity(locked_info) != source_root_identity:
            raise SuccessorAnchorError("successor activation source changed before install")
        existing_entries = _directory_names(parent, maximum=2)
        if existing_entries - {activation.CURRENT_DIRECTORY_NAME}:
            raise SuccessorAnchorError(
                "successor activation source is not empty for anchor install"
            )
        _mkdir_stage(parent, stage_name)
        stage_fd = _open_child_directory(parent, stage_name)
        _require_directory(stage_fd, owner=_root_owner_uid(), modes={0o700})
        for name, source in sources.items():
            _write_new_file(stage_fd, name, source.payload, final_mode=0o444)
        _write_installed_recovery(
            stage_fd,
            verified_checkpoint.checkpoint_sha256,
            source_recovery,
            source_objects,
        )
        stage_path = source_root / stage_name
        receipt = activation.seal_successor_installation_receipt(
            stage_path / activation.INSTALLATION_RECEIPT_FILENAME,
            config_path=stage_path / activation.SOURCE_CONFIG_FILENAME,
            operator_consent_path=stage_path / activation.OPERATOR_CONSENT_FILENAME,
            legacy_signed_directive_path=stage_path / activation.LEGACY_SIGNED_DIRECTIVE_FILENAME,
            initial_successor_page_path=stage_path
            / activation.INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
            signed_host_artifact_path=stage_path / activation.SIGNED_HOST_ARTIFACT_FILENAME,
            worker_limits_path=stage_path / activation.WORKER_LIMITS_FILENAME,
            host_observer_config_path=stage_path / activation.HOST_OBSERVER_FILENAME,
            recovery_archive_path=recovery_archive_path,
            recovery_limits=recovery_limits,
            verified_host_tree=verified_host_tree,
            verified_checkpoint=verified_checkpoint,
        )
        installed, installed_objects = load_installed_retained_checkpoint_archive(
            stage_path / activation.RECOVERY_DIRECTORY_NAME / verified_checkpoint.checkpoint_sha256,
            expected_sha256=verified_checkpoint.checkpoint_sha256,
            owner=_root_owner_uid(),
            limits=recovery_limits,
        )
        if (installed, installed_objects) != (source_recovery, source_objects):
            raise SuccessorAnchorError("installed recovery archive readback differs")
        os.fchmod(stage_fd, 0o555)
        os.fsync(stage_fd)
        for source in sources.values():
            _recheck_source(source)
        validate_checkpoint_for_successor(
            verified_checkpoint,
            validator_hotkey=config.validator_hotkey,
            predecessor_directive_sha256=receipt.legacy_predecessor_directive_sha256,
            minimum_finalized_block=receipt.legacy_predecessor_accepted_at_finalized_block,
        )
        verified_host_tree.recheck()
        if load_retained_checkpoint_archive(
            recovery_archive_path,
            expected_sha256=verified_checkpoint.checkpoint_sha256,
            owner=service_uid,
            limits=recovery_limits,
        ) != (source_recovery, source_objects):
            raise SuccessorAnchorError("recovery source changed during anchor install")
        final_parent_info = _require_directory(parent, owner=service_uid, modes={0o555})
        if _stable_directory_identity(final_parent_info) != source_root_identity:
            raise SuccessorAnchorError("successor activation source changed during install")
        named_stage = _open_child_directory(parent, stage_name)
        try:
            named_stage_info = _require_directory(
                named_stage,
                owner=_root_owner_uid(),
                modes={0o555},
            )
            if _fingerprint(named_stage_info) != _fingerprint(os.fstat(stage_fd)):
                raise SuccessorAnchorError("successor anchor staging directory changed")
        finally:
            os.close(named_stage)
        if _directory_names(parent, maximum=3) != existing_entries | {stage_name}:
            raise SuccessorAnchorError("successor activation source changed during install")
        _rename_noreplace(parent, stage_name, activation.ANCHOR_DIRECTORY_NAME)
        os.fsync(parent)
    except BlockingIOError as error:
        raise SuccessorAnchorError("successor activation source is busy") from error
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        os.close(parent)
    result = _load_materialized_anchor(config, allow_parent_repair=False)
    if result.receipt != receipt:
        raise SuccessorAnchorError("installed anchor receipt changed after rename")
    validate_checkpoint_for_successor(
        verified_checkpoint,
        validator_hotkey=result.config.validator_hotkey,
        predecessor_directive_sha256=result.receipt.legacy_predecessor_directive_sha256,
        minimum_finalized_block=result.receipt.legacy_predecessor_accepted_at_finalized_block,
    )
    verified_host_tree.recheck()
    return result


def load_materialized_successor_anchor(config_path: Path) -> MaterializedSuccessorAnchor:
    """Reload an installed anchor only when its service parent is immutable."""

    config = parse_canonical_validator_supervisor_config(
        _read_source(
            config_path,
            maximum_bytes=MAX_SUPERVISOR_DOCUMENT_BYTES,
            modes=frozenset({0o400, 0o440, 0o444, 0o600, 0o640}),
        ).payload
    )
    return _load_materialized_anchor(config, allow_parent_repair=False)


def load_materialized_successor_anchor_for_repair(
    config_path: Path,
) -> MaterializedSuccessorAnchor:
    """Reload an intact anchor while repairing only a 0755 source parent."""

    config = parse_canonical_validator_supervisor_config(
        _read_source(
            config_path,
            maximum_bytes=MAX_SUPERVISOR_DOCUMENT_BYTES,
            modes=frozenset({0o400, 0o440, 0o444, 0o600, 0o640}),
        ).payload
    )
    return _load_materialized_anchor(config, allow_parent_repair=True)


def validate_materialized_successor_anchor(anchor: MaterializedSuccessorAnchor) -> None:
    _validate_anchor_capability(anchor, allow_parent_repair=False)


def validate_materialized_successor_anchor_for_repair(
    anchor: MaterializedSuccessorAnchor,
) -> None:
    _validate_anchor_capability(anchor, allow_parent_repair=True)


def verify_materialized_current_history(
    anchor: MaterializedSuccessorAnchor,
    page: SuccessorSupervisorDirectivePage,
) -> SuccessorSupervisorDirectiveState:
    """Verify a rolling page against the sealed initial state without activating it."""

    validate_materialized_successor_anchor(anchor)
    return _verify_materialized_current_history(anchor, page)


def verify_materialized_current_history_for_repair(
    anchor: MaterializedSuccessorAnchor,
    page: SuccessorSupervisorDirectivePage,
) -> SuccessorSupervisorDirectiveState:
    """Verify rolling history while repairing only a widened source parent."""

    validate_materialized_successor_anchor_for_repair(anchor)
    return _verify_materialized_current_history(anchor, page)


def _verify_materialized_current_history(
    anchor: MaterializedSuccessorAnchor,
    page: SuccessorSupervisorDirectivePage,
) -> SuccessorSupervisorDirectiveState:
    page = parse_canonical_successor_supervisor_directive_history(canonical_json_bytes(page))
    return activation._verify_staged_current_history(
        page,
        config=anchor.config,
        consent=anchor.operator_consent,
        initial_state=anchor.initial_state,
    )


def _load_materialized_anchor(
    expected_config: ValidatorSupervisorConfig,
    *,
    allow_parent_repair: bool,
) -> MaterializedSuccessorAnchor:
    snapshot = _snapshot_anchor(expected_config, allow_parent_repair=allow_parent_repair)
    value = MaterializedSuccessorAnchor(
        source_root=successor_activation_source_root(snapshot.config),
        config=snapshot.config,
        operator_consent=snapshot.consent,
        worker_execution_limits=snapshot.limits,
        observer_config=snapshot.observer_config,
        receipt=snapshot.receipt,
        receipt_sha256=activation.successor_installation_receipt_sha256(snapshot.receipt),
        v3_state=snapshot.v3_state,
        v3_signed_bytes=snapshot.v3_signed_bytes,
        initial_page=snapshot.initial_page,
        initial_state=snapshot.initial_state,
        recovery=snapshot.recovery,
        service_uid=snapshot.service_uid,
        _source_parent_identity=snapshot.source_parent_identity,
        _source_root_identity=snapshot.source_root_identity,
        _anchor_snapshot_sha256=snapshot.snapshot_sha256,
        _issuer=_ANCHOR_TOKEN,
    )
    object.__setattr__(value, "_binding", _anchor_binding(value))
    _validate_anchor_capability(value, allow_parent_repair=allow_parent_repair)
    return value


def _validate_anchor_capability(
    anchor: MaterializedSuccessorAnchor,
    *,
    allow_parent_repair: bool,
) -> None:
    if (
        type(anchor) is not MaterializedSuccessorAnchor
        or anchor._issuer is not _ANCHOR_TOKEN
        or anchor._binding != _anchor_binding(anchor)
    ):
        raise SuccessorAnchorError("successor anchor capability is absent or altered")
    snapshot = _snapshot_anchor(anchor.config, allow_parent_repair=allow_parent_repair)
    if (
        snapshot.source_parent_identity != anchor._source_parent_identity
        or snapshot.source_root_identity != anchor._source_root_identity
        or snapshot.snapshot_sha256 != anchor._anchor_snapshot_sha256
    ):
        raise SuccessorAnchorError("materialized successor anchor changed")


def _snapshot_anchor(
    expected_config: ValidatorSupervisorConfig,
    *,
    allow_parent_repair: bool,
) -> _AnchorSnapshot:
    source_root, service_uid, parent_identity, root_identity = _validate_source_hierarchy(
        expected_config, allow_parent_repair=allow_parent_repair
    )
    anchor_path = source_root / activation.ANCHOR_DIRECTORY_NAME
    anchor_fd = _open_directory(anchor_path)
    try:
        anchor_info = _require_directory(anchor_fd, owner=_root_owner_uid(), modes={0o555})
        if _directory_names(anchor_fd, maximum=len(_ANCHOR_ENTRIES)) != set(_ANCHOR_ENTRIES):
            raise SuccessorAnchorError("successor anchor has an unexpected entry set")
        receipt_bytes = _read_anchor_control(
            anchor_fd,
            activation.INSTALLATION_RECEIPT_FILENAME,
            activation.MAX_SUCCESSOR_INSTALLATION_RECEIPT_BYTES,
        )
        receipt = activation.parse_canonical_successor_installation_receipt(receipt_bytes)
        controls = activation._read_bound_controls(
            anchor_fd,
            receipt,
            owner=_root_owner_uid(),
        )
    finally:
        os.close(anchor_fd)
    config = parse_canonical_validator_supervisor_config(
        controls[activation.SOURCE_CONFIG_FILENAME]
    )
    expected_config = ValidatorSupervisorConfig.model_validate_json(
        canonical_json_bytes(expected_config), strict=True
    )
    if config != expected_config or successor_activation_source_root(config) != source_root:
        raise SuccessorAnchorError("successor anchor config differs from its backing root")
    consent = parse_canonical_successor_operator_consent(
        controls[activation.OPERATOR_CONSENT_FILENAME]
    )
    legacy_signed: SignedSupervisorDirective = parse_canonical_signed_supervisor_directive(
        controls[activation.LEGACY_SIGNED_DIRECTIVE_FILENAME]
    )
    limits = activation._parse_worker_execution_limits(controls[activation.WORKER_LIMITS_FILENAME])
    observer_config = activation._parse_host_observer_config(
        controls[activation.HOST_OBSERVER_FILENAME]
    )
    activation._verify_receipt_controls(
        receipt,
        config=config,
        consent=consent,
        legacy_signed=legacy_signed,
        host_bytes=controls[activation.SIGNED_HOST_ARTIFACT_FILENAME],
        worker_limits_bytes=controls[activation.WORKER_LIMITS_FILENAME],
        observer_config_bytes=controls[activation.HOST_OBSERVER_FILENAME],
    )
    initial_page = parse_canonical_successor_supervisor_directive_history(
        controls[activation.INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME]
    )
    v3_state = activation._legacy_state(config, consent, legacy_signed)
    initial_state = activation._verify_initial_successor_history(
        initial_page,
        config=config,
        consent=consent,
        v3_state=v3_state,
        legacy_signed_bytes=controls[activation.LEGACY_SIGNED_DIRECTIVE_FILENAME],
        accepted_block=receipt.checkpoint_finalized_block,
    )
    recovery_root = anchor_path / activation.RECOVERY_DIRECTORY_NAME
    recovery_fd = _open_directory(recovery_root)
    try:
        recovery_info = _require_directory(recovery_fd, owner=_root_owner_uid(), modes={0o555})
        if _directory_names(recovery_fd, maximum=1) != {receipt.checkpoint_sha256}:
            raise SuccessorAnchorError("successor anchor recovery set is not exact")
    finally:
        os.close(recovery_fd)
    recovery, objects = load_installed_retained_checkpoint_archive(
        recovery_root / receipt.checkpoint_sha256,
        expected_sha256=receipt.checkpoint_sha256,
        owner=_root_owner_uid(),
        limits=receipt.recovery_limits,
    )
    activation._verify_retained_recovery_body(receipt, recovery)
    values = {
        "schema": "umi-materialized-successor-anchor-snapshot/1",
        "anchor_identity": _json_identity(_fingerprint(anchor_info)),
        "recovery_root_identity": _json_identity(_fingerprint(recovery_info)),
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "controls": {
            name: hashlib.sha256(payload).hexdigest() for name, payload in sorted(controls.items())
        },
        "initial_state_sha256": hashlib.sha256(canonical_json_bytes(initial_state)).hexdigest(),
        "recovery_sha256": hashlib.sha256(canonical_json_bytes(recovery)).hexdigest(),
        "recovery_objects": {
            name: hashlib.sha256(payload).hexdigest() for name, payload in sorted(objects.items())
        },
    }
    return _AnchorSnapshot(
        parent_identity,
        root_identity,
        service_uid,
        hashlib.sha256(canonical_json_bytes(values)).hexdigest(),
        config,
        consent,
        limits,
        observer_config,
        receipt,
        v3_state,
        controls[activation.LEGACY_SIGNED_DIRECTIVE_FILENAME],
        initial_page,
        initial_state,
        recovery,
    )


def _write_installed_recovery(
    anchor_fd: int,
    checkpoint_sha256: str,
    body: RecoveryCheckpointBody,
    objects: dict[str, bytes],
) -> None:
    os.mkdir(activation.RECOVERY_DIRECTORY_NAME, 0o700, dir_fd=anchor_fd)
    recovery_fd = _open_child_directory(anchor_fd, activation.RECOVERY_DIRECTORY_NAME)
    checkpoint_fd = objects_fd = -1
    try:
        os.mkdir(checkpoint_sha256, 0o700, dir_fd=recovery_fd)
        checkpoint_fd = _open_child_directory(recovery_fd, checkpoint_sha256)
        os.mkdir("objects", 0o700, dir_fd=checkpoint_fd)
        objects_fd = _open_child_directory(checkpoint_fd, "objects")
        for name, payload in sorted(objects.items()):
            if len(name) != 64 or any(character not in "0123456789abcdef" for character in name):
                raise SuccessorAnchorError("recovery object name is not a digest")
            _write_new_file(objects_fd, name, payload, final_mode=0o444)
        _write_new_file(
            checkpoint_fd,
            "checkpoint.json",
            canonical_json_bytes(body),
            final_mode=0o444,
        )
        os.fchmod(objects_fd, 0o555)
        os.fsync(objects_fd)
        os.fchmod(checkpoint_fd, 0o555)
        os.fsync(checkpoint_fd)
        os.fchmod(recovery_fd, 0o555)
        os.fsync(recovery_fd)
    finally:
        if objects_fd >= 0:
            os.close(objects_fd)
        if checkpoint_fd >= 0:
            os.close(checkpoint_fd)
        os.close(recovery_fd)


def _read_source(path: Path, *, maximum_bytes: int, modes: frozenset[int]) -> _SourceFile:
    path = _canonical_absolute(path, "successor control source")
    parent = _open_directory(path.parent)
    try:
        payload, identity = _read_regular(
            parent,
            path.name,
            owner=_root_owner_uid(),
            maximum_bytes=maximum_bytes,
            modes=modes,
        )
    finally:
        os.close(parent)
    return _SourceFile(path, payload, identity, maximum_bytes, modes)


def _recheck_source(source: _SourceFile) -> None:
    observed = _read_source(
        source.path,
        maximum_bytes=source.maximum_bytes,
        modes=source.modes,
    )
    if observed.identity != source.identity or observed.payload != source.payload:
        raise SuccessorAnchorError("successor control source changed during materialization")


def _require_private_control_parent(path: Path) -> None:
    descriptor = _open_directory(path)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != _root_owner_uid() or stat.S_IMODE(info.st_mode) not in {0o700, 0o750}:
            raise SuccessorAnchorError("successor control staging parent is not private")
    finally:
        os.close(descriptor)


def _validate_source_hierarchy(
    config: ValidatorSupervisorConfig,
    *,
    allow_parent_repair: bool,
) -> tuple[Path, int, tuple[int, ...], tuple[int, ...]]:
    source_root = successor_activation_source_root(config)
    state_root = source_root.parents[1]
    state_fd = _open_directory(state_root)
    parent_fd = source_fd = -1
    try:
        state_info = os.fstat(state_fd)
        if not stat.S_ISDIR(state_info.st_mode) or stat.S_IMODE(state_info.st_mode) != 0o700:
            raise SuccessorAnchorError("successor state root is not private")
        service_uid = state_info.st_uid
        _validate_service_uid(service_uid)
        parent_fd = _open_child_directory(state_fd, "successor-v4")
        parent_info = _require_directory(parent_fd, owner=service_uid, modes={0o700})
        source_fd = _open_child_directory(parent_fd, ACTIVATION_SOURCE_DIRECTORY_NAME)
        modes = {0o555, 0o755} if allow_parent_repair else {0o555}
        source_info = _require_directory(source_fd, owner=service_uid, modes=modes)
        names = _directory_names(source_fd, maximum=2)
        if not names <= {activation.ANCHOR_DIRECTORY_NAME, activation.CURRENT_DIRECTORY_NAME}:
            raise SuccessorAnchorError("successor activation source has unexpected entries")
        return (
            source_root,
            service_uid,
            _stable_directory_identity(parent_info),
            _stable_directory_identity(source_info),
        )
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(state_fd)


def _read_anchor_control(directory: int, name: str, maximum_bytes: int) -> bytes:
    payload, _ = _read_regular(
        directory,
        name,
        owner=_root_owner_uid(),
        maximum_bytes=maximum_bytes,
        modes=frozenset({0o444}),
    )
    return payload


def _read_regular(
    directory: int,
    name: str,
    *,
    owner: int,
    maximum_bytes: int,
    modes: frozenset[int],
) -> tuple[bytes, tuple[int, ...]]:
    _safe_name(name)
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=directory,
        )
    except OSError as error:
        raise SuccessorAnchorError("could not open successor anchor file") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in modes
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise SuccessorAnchorError("successor anchor file is unsafe or oversized")
        body = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise SuccessorAnchorError("successor anchor file was truncated")
            body.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise SuccessorAnchorError("successor anchor file grew while reading")
        after = os.fstat(descriptor)
        if _fingerprint(before) != _fingerprint(after):
            raise SuccessorAnchorError("successor anchor file changed while reading")
        return bytes(body), _fingerprint(after)
    finally:
        os.close(descriptor)


def _write_new_file(directory: int, name: str, payload: bytes, *, final_mode: int) -> None:
    _safe_name(name)
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o400,
        dir_fd=directory,
    )
    try:
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise SuccessorAnchorError("successor anchor write made no progress")
            view = view[count:]
        os.fsync(descriptor)
        os.fchmod(descriptor, final_mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir_stage(parent: int, name: str) -> None:
    os.mkdir(name, 0o700, dir_fd=parent)


def _rename_noreplace(
    parent: int, source: str, destination: str, *, destination_parent: int | None = None
) -> None:
    _safe_name(source)
    _safe_name(destination)
    if sys.platform != "linux":
        raise SuccessorAnchorError("atomic anchor install requires Linux renameat2")
    library = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = library.renameat2
    except AttributeError as error:
        raise SuccessorAnchorError("host libc lacks renameat2") from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    target = parent if destination_parent is None else destination_parent
    if renameat2(parent, os.fsencode(source), target, os.fsencode(destination), _RENAME_NOREPLACE):
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise SuccessorAnchorError("successor anchor already exists")
        raise SuccessorAnchorError("could not atomically install successor anchor") from OSError(
            number, os.strerror(number)
        )


def _open_directory(path: Path) -> int:
    path = _canonical_absolute(path, "successor anchor directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for name in path.parts[1:]:
            child = os.open(name, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_child_directory(parent: int, name: str) -> int:
    _safe_name(name)
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
    except OSError as error:
        raise SuccessorAnchorError("could not open successor anchor directory") from error


def _require_directory(
    descriptor: int,
    *,
    owner: int,
    modes: set[int],
) -> os.stat_result:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner
        or stat.S_IMODE(info.st_mode) not in modes
    ):
        raise SuccessorAnchorError("successor anchor directory owner or mode is unsafe")
    return info


def _directory_names(descriptor: int, *, maximum: int) -> set[str]:
    names: set[str] = set()
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if len(names) >= maximum or entry.name in names or entry.is_symlink():
                raise SuccessorAnchorError("successor anchor directory exceeds its entry bound")
            if not entry.is_file(follow_symlinks=False) and not entry.is_dir(follow_symlinks=False):
                raise SuccessorAnchorError("successor anchor contains a special file")
            names.add(entry.name)
    return names


def _stable_directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid)


def _json_identity(value: tuple[int, ...]) -> list[str]:
    return [str(item) for item in value]


def _anchor_binding(anchor: MaterializedSuccessorAnchor) -> str:
    values = {
        "schema": "umi-materialized-successor-anchor-capability/1",
        "source_root": str(anchor.source_root),
        "service_uid": anchor.service_uid,
        "config_sha256": successor_source_config_sha256(anchor.config),
        "consent_sha256": hashlib.sha256(canonical_json_bytes(anchor.operator_consent)).hexdigest(),
        "limits_sha256": hashlib.sha256(
            canonical_json_bytes(anchor.worker_execution_limits)
        ).hexdigest(),
        "observer_config_sha256": hashlib.sha256(
            canonical_json_bytes(anchor.observer_config)
        ).hexdigest(),
        "receipt_sha256": anchor.receipt_sha256,
        "receipt_body_sha256": hashlib.sha256(canonical_json_bytes(anchor.receipt)).hexdigest(),
        "v3_state_sha256": hashlib.sha256(canonical_json_bytes(anchor.v3_state)).hexdigest(),
        "v3_signed_sha256": hashlib.sha256(anchor.v3_signed_bytes).hexdigest(),
        "initial_page_sha256": hashlib.sha256(
            canonical_json_bytes(anchor.initial_page)
        ).hexdigest(),
        "initial_state_sha256": hashlib.sha256(
            canonical_json_bytes(anchor.initial_state)
        ).hexdigest(),
        "recovery_sha256": hashlib.sha256(canonical_json_bytes(anchor.recovery)).hexdigest(),
        "source_parent_identity": _json_identity(anchor._source_parent_identity),
        "source_root_identity": _json_identity(anchor._source_root_identity),
        "anchor_snapshot_sha256": anchor._anchor_snapshot_sha256,
    }
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()


def _canonical_absolute(path: Path, label: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{label} path must be a Path")
    if not path.is_absolute() or path != Path(os.path.normpath(path)) or path == Path("/"):
        raise SuccessorAnchorError(f"{label} path must be canonical and absolute")
    return path


def _safe_name(name: str) -> None:
    if not isinstance(name, str) or not name or name in {".", ".."} or "/" in name or "\0" in name:
        raise SuccessorAnchorError("successor anchor filename is unsafe")


def _root_owner_uid() -> int:
    return 0


def _validate_service_uid(value: int) -> None:
    if type(value) is not int or value <= 0 or value == _root_owner_uid():
        raise SuccessorAnchorError("successor activation source needs a dedicated service owner")


def _require_root_linux() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SuccessorAnchorError("successor anchor materialization requires root on Linux")


__all__ = [
    "ACTIVATION_SOURCE_DIRECTORY_NAME",
    "ANCHOR_STAGING_PREFIX",
    "MaterializedSuccessorAnchor",
    "SuccessorAnchorError",
    "load_materialized_successor_anchor",
    "load_materialized_successor_anchor_for_repair",
    "materialize_successor_anchor",
    "successor_activation_source_root",
    "validate_materialized_successor_anchor",
    "validate_materialized_successor_anchor_for_repair",
    "verify_materialized_current_history",
    "verify_materialized_current_history_for_repair",
]
