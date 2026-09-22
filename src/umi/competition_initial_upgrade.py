"""Initial, root-operated successor upgrade for one supported systemd service.

The pre-stop rehearsal is wallet-free. A stopped lease, two owned chain reads
and an immutable recovery archive are required before source publication. The
existing resume commands handle failures after publication intent. Coordinator
instances retain their RootDirectory and use a private view of their old paths.
"""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import hashlib
import json
import os
import platform
import pwd
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import competition_host_activation as activation
from . import competition_host_anchor as anchors
from .bridge.transactions import RegistrationBridgeTransactionJournal
from .competition_bridge_recovery import JOURNAL as BRIDGE_JOURNAL
from .competition_bridge_recovery import audit_bridge_history
from .competition_chain_state import OwnedCompetitionChainObservation
from .competition_host_artifacts import (
    _STAGE_PARENT,
    SignedSuccessorHostArtifact,
    VerifiedHostTree,
    _ancestor_identity,
    _ancestor_paths,
    _read_tree,
)
from .competition_host_bundle import stage_successor_host_bundle
from .competition_host_observer import (
    StoppedBridgeObservation,
    StoppedUpgradeObserver,
)
from .competition_host_service import _path, validate_host_service_resources
from .competition_host_start import _systemctl, start_committed_successor_service
from .competition_host_switch import commit_successor_service_switch
from .competition_host_upgrade import (
    HostUpgradeError,
    StoppedSupervisor,
    _require_root_linux,
    hold_stopped_supervisor,
    inspect_legacy_service,
)
from .competition_recovery import (
    RecoveryLimits,
    SignedBootstrapEligibilityManifest,
    SignedSimpleBootstrapLease,
    _snapshot_kwargs,
    load_recovery_checkpoint_context,
    prepare_recovery_checkpoint,
    snapshot_legacy_bootstrap,
    verify_recovery_checkpoint,
)
from .competition_supervisor import (
    SuccessorSupervisorDirectivePage,
    SuccessorSupervisorOperatorConsent,
    parse_canonical_successor_operator_consent,
    parse_canonical_successor_supervisor_directive_history,
)
from .competition_switch_recovery import exclusive_upgrade_operation
from .competition_upgrade import _fingerprint, _open_without_links, _Reader
from .competition_upgrade_namespace import prepare_upgrade_observer_namespace
from .protocol import canonical_json_bytes
from .validator_supervisor import (
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    SignedSupervisorDirective,
    ValidatorSupervisorConfig,
    ValidatorSupervisorError,
    advance_supervisor_directive_history_state,
    parse_canonical_signed_supervisor_directive,
    parse_canonical_supervisor_directive_state,
    parse_canonical_validator_supervisor_config,
)
from .validator_supervisor_runtime import DIRECTIVE_STATE_FILENAME

_PREFLIGHT_PARENT = Path("/var/lib/umi-successor-preflight")
_SEALED = frozenset({0o400, 0o440, 0o444})


@dataclass(frozen=True)
class _Controls:
    sources: dict[str, anchors._SourceFile]
    config: ValidatorSupervisorConfig
    consent: SuccessorSupervisorOperatorConsent
    legacy: SignedSupervisorDirective
    page: SuccessorSupervisorDirectivePage
    signed_host: SignedSuccessorHostArtifact

    def recheck(self):
        for source in self.sources.values():
            anchors._recheck_source(source)

    def paths(self):
        return {
            argument: self.sources[name].path for name, argument, _, _ in anchors._SOURCE_CONTROLS
        }


def _controls(config_path: Path, controls: Path) -> _Controls:
    anchors._require_private_control_parent(controls)
    sources = {
        name: anchors._read_source(
            config_path if name == activation.SOURCE_CONFIG_FILENAME else controls / name,
            maximum_bytes=maximum,
            modes=modes,
        )
        for name, _, maximum, modes in anchors._SOURCE_CONTROLS
    }
    config_bytes = sources[activation.SOURCE_CONFIG_FILENAME].payload
    config = parse_canonical_validator_supervisor_config(config_bytes)
    from .competition_coordinator_namespace import active_coordinator_view

    view = active_coordinator_view()
    if view is not None:
        for logical in (
            config.state_root,
            config.worker_state_root,
            config.release_root,
            config.operator_input_root,
            config.wallet.path,
        ):
            view.layout.physical(Path(logical))
    consent = parse_canonical_successor_operator_consent(
        sources[activation.OPERATOR_CONSENT_FILENAME].payload
    )
    if consent.source_config_sha256 != hashlib.sha256(config_bytes).hexdigest():
        raise HostUpgradeError("operator consent names another config")
    legacy_bytes = sources[activation.LEGACY_SIGNED_DIRECTIVE_FILENAME].payload
    legacy = parse_canonical_signed_supervisor_directive(legacy_bytes)
    state = activation._legacy_state(config, consent, legacy)
    if (
        advance_supervisor_directive_history_state(
            legacy,
            config=config,
            finalized_block=state.accepted_at_finalized_block,
            prior_state=state,
        )
        != state
    ):
        raise HostUpgradeError("legacy authority differs from retained consent")
    page = parse_canonical_successor_supervisor_directive_history(
        sources[activation.INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME].payload
    )
    if not page.directives:
        raise HostUpgradeError("initial successor history is empty")
    # Authenticate the complete history now. Fresh owned finality checks its
    # actual activation window again after stop, before a receipt is sealed.
    activation._verify_initial_successor_history(
        page,
        config=config,
        consent=consent,
        v3_state=state,
        legacy_signed_bytes=legacy_bytes,
        accepted_block=max(
            state.accepted_at_finalized_block,
            consent.authorized_at_finalized_block,
            page.directives[-1].directive.valid_from_block,
            *(s.directive.issued_at_block for s in page.directives),
        ),
    )
    if page.directives[-1].directive.release is None:
        raise HostUpgradeError("initial installation needs a signed successor release")
    signed_host = activation._parse_and_verify_host_artifact(
        sources[activation.SIGNED_HOST_ARTIFACT_FILENAME].payload,
        config=config,
        expected_manifest_sha256=consent.approved_host_manifest_sha256,
    )
    activation._parse_worker_execution_limits(sources[activation.WORKER_LIMITS_FILENAME].payload)
    observer = activation._parse_host_observer_config(
        sources[activation.HOST_OBSERVER_FILENAME].payload
    )
    activation._verify_host_observer_config(
        observer,
        config=config,
        checkpoint_genesis_hash="0x" + observer.chain.chain_pin.genesis_block_hash,
    )
    result = _Controls(sources, config, consent, legacy, page, signed_host)
    result.recheck()
    return result


def _directory(
    path: Path, *, owner: int, mode: int, group: int, parent_owner: int, parent_modes: set[int]
):
    """Create only one exact child; never chmod/chown a pre-existing path."""
    parent = _open_without_links(path.parent)
    descriptor = -1
    try:
        info = os.fstat(parent)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != parent_owner
            or stat.S_IMODE(info.st_mode) not in parent_modes
        ):
            raise HostUpgradeError("upgrade directory parent differs")
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
        except FileExistsError:
            created = False
        else:
            created = True
        descriptor = os.open(
            path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
        )
        if created:
            os.fchown(descriptor, owner, group)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            os.fsync(parent)
        info = os.fstat(descriptor)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (owner, group, mode):
            raise HostUpgradeError("existing upgrade directory has a different owner or mode")
        named = _open_without_links(path)
        try:
            if _fingerprint(os.fstat(named)) != _fingerprint(info):
                raise HostUpgradeError("upgrade directory changed during preparation")
        finally:
            os.close(named)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _service_identity(control: _Controls, unit_name: str):
    descriptor = _open_without_links(Path(control.config.state_root))
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid <= 0
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise HostUpgradeError("installed service state is not owned and private")
        user = pwd.getpwuid(info.st_uid)
    finally:
        os.close(descriptor)
    unit = inspect_legacy_service(
        unit_name, control.sources[activation.SOURCE_CONFIG_FILENAME].path, user.pw_uid
    )
    reader = _Reader(user.pw_uid)
    state = parse_canonical_supervisor_directive_state(
        reader.file(
            Path(control.config.state_root) / DIRECTIVE_STATE_FILENAME,
            "highwater",
            MAX_SUPERVISOR_DOCUMENT_BYTES,
            modes={0o600},
        ),
        trust_policy=control.config.trust_policy(),
    )
    if state != activation._legacy_state(control.config, control.consent, control.legacy):
        raise HostUpgradeError("running legacy history moved beyond the approved predecessor")
    control.recheck()
    reader.unchanged()
    return user, unit


def _prepare_layout(control, user, controls_path, recovery_root):
    state = Path(control.config.state_root)
    for path, owner, group, mode, parent_owner, parent_modes in (
        (_STAGE_PARENT, 0, 0, 0o755, 0, {0o755}),
        (state / "successor-v4", user.pw_uid, user.pw_gid, 0o700, user.pw_uid, {0o700}),
        (
            anchors.successor_activation_source_root(control.config),
            user.pw_uid,
            user.pw_gid,
            0o555,
            user.pw_uid,
            {0o700},
        ),
        (state / "successor-observer", user.pw_uid, user.pw_gid, 0o700, user.pw_uid, {0o700}),
        (controls_path / "finality-state", 0, 0, 0o700, 0, {0o700, 0o750}),
    ):
        _directory(
            path,
            owner=owner,
            group=group,
            mode=mode,
            parent_owner=parent_owner,
            parent_modes=parent_modes,
        )
    for root in (
        control.config.state_root,
        control.config.worker_state_root,
        control.config.release_root,
        control.config.operator_input_root,
        control.config.wallet.path,
    ):
        other = Path(root)
        if (
            recovery_root == other
            or other in recovery_root.parents
            or recovery_root in other.parents
        ):
            raise HostUpgradeError("recovery archive overlaps an installed root")
    _Reader(user.pw_uid).directory(recovery_root, modes={0o700})
    _retain_interrupted_anchors(control.config, user)


def _retain_interrupted_anchors(config, user):
    """Move unpublished root-owned stages aside intact; never accept their authority.

    A retry builds a new anchor from fresh stopped-state reconciliation. The
    retained directory is outside activation-source and cannot be loaded as its
    anchor. Atomic no-replace moves also make interruption of this step resumable.
    """
    _require_root_linux()
    source = anchors.successor_activation_source_root(config)
    retained = source.parent / "retained-anchors"
    pattern = re.compile(re.escape(anchors.ANCHOR_STAGING_PREFIX) + r"[0-9a-f]{32}")
    root_uid = anchors._root_owner_uid()
    parent = _open_without_links(source)
    destination = -1
    try:
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(parent)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != user.pw_uid
            or stat.S_IMODE(info.st_mode) != 0o555
        ):
            raise HostUpgradeError("interrupted anchor source is not sealed")
        names = anchors._directory_names(parent, maximum=9)
        partials = sorted(names - {activation.ANCHOR_DIRECTORY_NAME})
        if any(not pattern.fullmatch(name) for name in partials):
            raise HostUpgradeError("initial anchor source has unexpected entries")
        if not partials:
            return
        _directory(
            retained,
            owner=root_uid,
            group=root_uid,
            mode=0o700,
            parent_owner=user.pw_uid,
            parent_modes={0o700},
        )
        destination = _open_without_links(retained)
        existing = anchors._directory_names(destination, maximum=8)
        if len(existing) + len(partials) > 8 or any(
            not pattern.fullmatch(name) for name in existing
        ):
            raise HostUpgradeError("retained anchor slots exhausted or unrecognized")
        if set(partials) & existing:
            raise HostUpgradeError("retained anchor name already exists")
        observed = {}
        for directory, children in ((parent, partials), (destination, existing)):
            for name in children:
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                )
                try:
                    child = os.fstat(descriptor)
                    if (
                        child.st_uid != root_uid
                        or stat.S_IMODE(child.st_mode) not in {0o700, 0o555}
                        or child.st_dev != os.fstat(destination).st_dev
                    ):
                        raise HostUpgradeError("unsafe or cross-filesystem anchor partial")
                    observed[(directory, name)] = _fingerprint(child)
                finally:
                    os.close(descriptor)
        for name in partials:
            if (
                _fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False))
                != observed[(parent, name)]
            ):
                raise HostUpgradeError("anchor partial changed before retention")
            anchors._rename_noreplace(parent, name, name, destination_parent=destination)
            os.fsync(destination)
            os.fsync(parent)
            if (
                _fingerprint(os.stat(name, dir_fd=destination, follow_symlinks=False))[:2]
                != observed[(parent, name)][:2]
            ):
                raise HostUpgradeError("retained anchor identity changed")
        named = _open_without_links(source)
        try:
            current = os.fstat(named)
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise HostUpgradeError("anchor source moved during retention")
        finally:
            os.close(named)
    finally:
        if destination >= 0:
            os.close(destination)
        os.close(parent)


def _historical_context(path):
    if path is None:
        return None, (), ()
    source = anchors._read_source(path, maximum_bytes=16 * 1024**2, modes=_SEALED)
    value = json.loads(source.payload)
    if not isinstance(value, dict) or set(value) != {"manifests", "leases"}:
        raise HostUpgradeError("recovery context needs exact manifest and lease lists")
    if any(not isinstance(value[key], list) or len(value[key]) > 256 for key in value):
        raise HostUpgradeError("recovery context exceeds its item bound")
    manifests = tuple(
        SignedBootstrapEligibilityManifest.model_validate(v) for v in value["manifests"]
    )
    leases = tuple(SignedSimpleBootstrapLease.model_validate(v) for v in value["leases"])
    if canonical_json_bytes({"manifests": manifests, "leases": leases}) != source.payload:
        raise HostUpgradeError("historical recovery context is not canonical")
    # Snapshot/reconciliation verifies the historical authorities and bindings.
    # These records cannot grant a new weight-writing authorization.
    return source, manifests, leases


def _retained_anchor(control, config_path):
    source = anchors.successor_activation_source_root(control.config)
    try:
        (source / activation.ANCHOR_DIRECTORY_NAME).lstat()
    except FileNotFoundError:
        return None
    anchor = anchors.load_materialized_successor_anchor(config_path)
    for name, original in control.sources.items():
        retained = anchors._read_source(
            source / activation.ANCHOR_DIRECTORY_NAME / name,
            maximum_bytes=original.maximum_bytes,
            modes=frozenset({0o444}),
        )
        if retained.payload != original.payload:
            raise HostUpgradeError("retained initial anchor differs from supplied controls")
    anchor.recheck()
    return anchor


async def _observe_stopped_history(
    stopped: StoppedSupervisor,
    observer: StoppedUpgradeObserver,
    limits: RecoveryLimits,
    manifests: tuple[SignedBootstrapEligibilityManifest, ...] = (),
    leases: tuple[SignedSimpleBootstrapLease, ...] = (),
) -> tuple[OwnedCompetitionChainObservation, StoppedBridgeObservation | None]:
    with snapshot_legacy_bootstrap(
        stopped.worker_state_root,
        **_snapshot_kwargs(stopped, limits, manifests, leases),
    ) as snapshot:
        # Classification authenticates the retained manifest/lease at its
        # historical preflight block. Request its commitment in the final owned
        # read; a later bridge row does not replace proof of the old anchor.
        anchors = {
            effect.manifest_sha256
            for effect in snapshot.manifest.effects
            if effect.classification in {"retained_anchor_receipt", "retained_weight_receipt"}
        }
        if len(anchors) > 1:
            raise HostUpgradeError("recovery requires multiple historical manifest anchors")
        manifest_anchor = next(iter(anchors), None)
        if BRIDGE_JOURNAL in snapshot._files:
            audit = audit_bridge_history(snapshot._files, hotkey=stopped.validator_hotkey)
            if any(type(j) is RegistrationBridgeTransactionJournal for _, j in audit.attempts):
                collected = await observer.observe_bridge(
                    audit, snapshot.sha256, manifest_anchor_sha256=manifest_anchor
                )
                return collected.observation, collected
        return await observer.observe(manifest_anchor_sha256=manifest_anchor), None


async def _switch_stopped(
    control,
    config_path,
    controls_path,
    unit_name,
    user,
    tree,
    recovery_root,
    limits,
    historical_manifests=(),
    historical_leases=(),
):
    with hold_stopped_supervisor(
        config_path=config_path,
        accepted_directive_bytes=control.sources[
            activation.LEGACY_SIGNED_DIRECTIVE_FILENAME
        ].payload,
        expected_hotkey=control.config.validator_hotkey,
        service_uid=user.pw_uid,
        unit_name=unit_name,
    ) as stopped:
        observer = StoppedUpgradeObserver(
            stopped=stopped,
            host_tree=tree,
            signed_host=control.signed_host,
            operator_consent_path=controls_path / activation.OPERATOR_CONSENT_FILENAME,
            observer_config_path=controls_path / activation.HOST_OBSERVER_FILENAME,
        )
        try:
            anchor = _retained_anchor(control, config_path)
            if anchor is None:
                observation, bridge_observation = await _observe_stopped_history(
                    stopped, observer, limits, historical_manifests, historical_leases
                )
                prepared = prepare_recovery_checkpoint(
                    stopped,
                    observation,
                    destination_root=recovery_root,
                    limits=limits,
                    historical_manifests=historical_manifests,
                    historical_leases=historical_leases,
                    bridge_observation=bridge_observation,
                )
                checkpoint_path = Path(prepared.checkpoint_path)
                checkpoint_sha = prepared.checkpoint_sha256
            else:
                checkpoint_sha = anchor.receipt.checkpoint_sha256
                checkpoint_path = recovery_root / checkpoint_sha
                historical_manifests, historical_leases = load_recovery_checkpoint_context(
                    checkpoint_path,
                    expected_sha256=checkpoint_sha,
                    owner=user.pw_uid,
                    limits=limits,
                )
            observation, bridge_observation = await _observe_stopped_history(
                stopped, observer, limits, historical_manifests, historical_leases
            )
            verified = verify_recovery_checkpoint(
                checkpoint_path,
                expected_checkpoint_sha256=checkpoint_sha,
                stopped=stopped,
                observation=observation,
                limits=limits,
                bridge_observation=bridge_observation,
            )
        finally:
            await observer.aclose()
        control.recheck()
        if anchor is None:
            anchor = anchors.materialize_successor_anchor(
                **control.paths(),
                recovery_archive_path=checkpoint_path,
                recovery_limits=limits,
                verified_host_tree=tree,
                verified_checkpoint=verified,
            )
        switched = commit_successor_service_switch(
            stopped=stopped, anchor=anchor, host_tree=tree, signed_host=control.signed_host
        )
    return switched


def _prestop_host_requirements(control: _Controls, tree: VerifiedHostTree):
    control.recheck()
    tree.recheck()
    observer = activation._parse_host_observer_config(
        control.sources[activation.HOST_OBSERVER_FILENAME].payload
    )
    validate_host_service_resources(control.signed_host, observer.chain)
    records = {item.path: item for item in control.signed_host.manifest.files}
    for name in (
        "src/umi/competition_initial_upgrade.py",
        "src/umi/competition_supervisor_cli.py",
        "src/umi/competition_supervisor_cleanup.py",
    ):
        if name not in records or records[name].mode != 0o444:
            raise HostUpgradeError("signed host lacks its fixed upgrade or lifecycle source")


def upgrade_successor_service(
    *,
    config_path: Path,
    unit_name: str,
    controls_path: Path,
    host_bundle: Path,
    oci_bundle: Path,
    recovery_root: Path,
    recovery_limits_path: Path,
    historical_context_path: Path | None = None,
) -> dict:
    """Preflight, stop, archive, switch and start one exact legacy installation."""
    from .competition_coordinator_namespace import ensure_coordinator_host_view

    _require_root_linux()
    ensure_coordinator_host_view(unit_name=unit_name, config_path=config_path)
    with exclusive_upgrade_operation(unit_name):
        control = _controls(config_path, controls_path)
        limit_source = anchors._read_source(
            recovery_limits_path, maximum_bytes=16384, modes=_SEALED
        )
        limits = RecoveryLimits.model_validate_json(limit_source.payload)
        if canonical_json_bytes(limits) != limit_source.payload:
            raise HostUpgradeError("recovery limits are not canonical")
        context_source, manifests, leases = _historical_context(historical_context_path)
        user, unit = _service_identity(control, unit_name)
        _prepare_layout(control, user, controls_path, recovery_root)
        _retained_anchor(control, config_path)
        tree = stage_successor_host_bundle(
            host_bundle,
            signed=control.signed_host,
            config=control.config,
            expected_manifest_sha256=control.consent.approved_host_manifest_sha256,
        )
        _prestop_host_requirements(control, tree)
        _rehearse_service(control, user, unit, tree, oci_bundle)
        # Set up the process-private mounts before asyncio can create threads.
        prepare_upgrade_observer_namespace(
            host_tree=tree, config=control.config, control_directory=controls_path
        )
        control.recheck()
        anchors._recheck_source(limit_source)
        if context_source is not None:
            anchors._recheck_source(context_source)
        tree.recheck()
        current_user, current_unit = _service_identity(control, unit_name)
        stable = (
            "Id",
            "User",
            "FragmentPath",
            "ExecStart",
            "DropInPaths",
            "OnFailure",
            "RootDirectory",
            "RootImage",
            "Slice",
        )
        if current_user != user or any(current_unit[k] != unit[k] for k in stable):
            raise HostUpgradeError("legacy service identity changed during rehearsal")
        _systemctl("stop", unit_name)
        switched = asyncio.run(
            _switch_stopped(
                control,
                config_path,
                controls_path,
                unit_name,
                user,
                tree,
                recovery_root,
                limits,
                manifests,
                leases,
            )
        )
        # The stopped context has released the old lock; the operator mutex is
        # still held through start and any exact-service failure containment.
        started = start_committed_successor_service(switched)
        return {
            "status": "successor_service_running",
            "unit_name": started.unit_name,
            "main_pid": started.main_pid,
            "host_manifest_sha256": started.host_manifest_sha256,
            "checkpoint_sha256": started.checkpoint_sha256,
            "service_started": True,
            "chain_submission_authorized": False,
        }


# Copy only the installed service's sandbox/resource properties into a new
# transient unit. No legacy lifecycle command, state/runtime directory manager,
# dependency or restart hook is executed by this wallet-free preflight.
_SANDBOX = frozenset(
    {
        "UMask",
        "WorkingDirectory",
        "CPUQuota",
        "TasksMax",
        "LimitNOFILE",
        "LimitCORE",
        "MemoryHigh",
        "MemoryMax",
        "OOMPolicy",
        "PrivateTmp",
        "KeyringMode",
        "RemoveIPC",
        "ProtectClock",
        "ProtectHome",
        "ProtectKernelModules",
        "ProtectSystem",
        "ProtectProc",
        "RestrictAddressFamilies",
        "RestrictRealtime",
        "LockPersonality",
        "MemoryDenyWriteExecute",
        "SystemCallArchitectures",
        "AmbientCapabilities",
        "Delegate",
        "ReadOnlyPaths",
        "ReadWritePaths",
    }
)
_IGNORED_SERVICE = frozenset(
    {
        "Type",
        "User",
        "Group",
        "ExecStartPre",
        "ExecStart",
        "Restart",
        "RestartSec",
        "TimeoutStartSec",
        "TimeoutStopSec",
        "KillMode",
        "StateDirectory",
        "StateDirectoryMode",
        "RuntimeDirectory",
        "RuntimeDirectoryMode",
        "RuntimeDirectoryPreserve",
    }
)


def _sandbox_properties(fragment: bytes, *, coordinator=None) -> list[str]:
    section, pending, result, seen = "", "", [], set()
    for raw in fragment.decode("utf-8", errors="strict").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        pending += line
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        line, pending = pending, ""
        if line.startswith("[") and line.endswith("]"):
            section = line
            if section not in {"[Unit]", "[Service]", "[Install]"}:
                raise HostUpgradeError("unsupported legacy unit section")
            continue
        key, equals, value = line.partition("=")
        extra = set()
        if coordinator:
            # Expand only the reviewed template fields. Arbitrary specifiers,
            # alternate mounts and unknown namespace directives still fail.
            exact = {
                "User": "umi-validator-uid%i",
                "Group": "umi-validator-uid%i",
                "RootDirectory": "/var/lib/umi-validator-hosts/uid%i",
                "RuntimeDirectory": "umi-validator-uid%i",
                "BindPaths": "/run/umi-validator-uid%i:/run/umi-validator-supervisor",
                "BindReadOnlyPaths": "/etc/resolv.conf:/etc/resolv.conf",
                "Slice": "umi-validators.slice",
                "MountAPIVFS": "true",
                "ConditionPathExists": (
                    "/var/lib/umi-validator-hosts/uid%i/etc/umi/migration-approved"
                ),
            }
            if key in exact:
                if value != exact[key]:
                    raise HostUpgradeError("coordinator template boundary differs from its adapter")
                value = value.replace("%i", coordinator.instance)
            elif key == "Description" and section == "[Unit]":
                value = value.replace("%i", coordinator.instance)
            extra = (
                {"ConditionPathExists"}
                if section == "[Unit]"
                else {"RootDirectory", "BindPaths", "BindReadOnlyPaths", "Slice", "MountAPIVFS"}
                if section == "[Service]"
                else set()
            )
        allowed = {
            "[Unit]": {"Description", "Documentation", "After", "Wants"},
            "[Install]": {"WantedBy"},
            "[Service]": _SANDBOX | _IGNORED_SERVICE,
        }.get(section, set()) | extra
        quota_percent = key == "CPUQuota" and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?%", value)
        if (
            not equals
            or key not in allowed
            or (section, key) in seen
            or ("%" in value and not quota_percent)
        ):
            raise HostUpgradeError("legacy unit needs a reviewed sandbox adapter")
        seen.add((section, key))
        if (
            section == "[Service]"
            and key in _SANDBOX
            and key not in {"ProtectHome", "ReadOnlyPaths", "ReadWritePaths"}
        ):
            result.append(key + "=" + value)
        elif section == "[Service]" and key in {"ReadOnlyPaths", "ReadWritePaths"}:
            # Every path is literal. Forward the original list along with the
            # extra successor paths below, without systemd specifier expansion.
            paths = []
            for path in value.split():
                if coordinator:
                    if not path.startswith("+"):
                        raise HostUpgradeError("coordinator sandbox path is not rooted")
                    if path == "+/run/umi-validator-supervisor":
                        continue  # The probe uses its own user-manager runtime.
                    paths.append("+" + _path(path[1:]))
                else:
                    paths.append(_path(path))
            result.append(key + "=" + " ".join(paths))
    if pending or ("[Service]", "ExecStart") not in seen:
        raise HostUpgradeError("legacy unit is incomplete")
    return result


def _copy_oci(bundle: Path, destination: Path, target, user):
    source = _open_without_links(bundle)
    output = -1
    try:
        before = os.fstat(source)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in _SEALED
            or before.st_size != target.release_bundle_size_bytes
        ):
            raise HostUpgradeError("OCI preflight source is not exactly root-sealed")
        output = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        digest, remaining = hashlib.sha256(), before.st_size
        while remaining:
            chunk = os.read(source, min(1024 * 1024, remaining))
            if not chunk:
                raise HostUpgradeError("OCI preflight source was truncated")
            remaining -= len(chunk)
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                count = os.write(output, view)
                if count <= 0:
                    raise HostUpgradeError("OCI preflight copy made no progress")
                view = view[count:]
        if (
            os.read(source, 1)
            or _fingerprint(os.fstat(source)) != _fingerprint(before)
            or digest.hexdigest() != target.release_bundle_sha256
        ):
            raise HostUpgradeError("OCI preflight source differs from signed bytes")
        # The existing extractor requires a private service-owned artifact.
        # The containing root-owned directory is mounted read-only in the probe.
        os.fchown(output, user.pw_uid, user.pw_gid)
        os.fchmod(output, 0o400)
        os.fsync(output)
    finally:
        if output >= 0:
            os.close(output)
        os.close(source)


def _rehearse_service(control, user, unit, tree: VerifiedHostTree, bundle: Path):
    from .competition_host_upgrade import _check_service_namespace

    layout = _check_service_namespace(unit["Id"], unit)
    record = next(
        (
            r
            for r in control.signed_host.manifest.files
            if r.path == "src/umi/competition_initial_upgrade.py"
        ),
        None,
    )
    if record is None:
        raise HostUpgradeError("signed host lacks its initial upgrade rehearsal entrypoint")
    fragment = anchors._read_source(
        Path(unit["FragmentPath"]),
        maximum_bytes=128 * 1024,
        modes=frozenset({0o400, 0o444, 0o600, 0o644}),
    )
    properties = _sandbox_properties(fragment.payload, coordinator=layout)
    _directory(
        _PREFLIGHT_PARENT, owner=0, group=0, mode=0o755, parent_owner=0, parent_modes={0o755}
    )
    own = _PREFLIGHT_PARENT / hashlib.sha256(canonical_json_bytes(control.config)).hexdigest()
    _directory(own, owner=0, group=user.pw_gid, mode=0o750, parent_owner=0, parent_modes={0o755})
    if sum(1 for _ in own.iterdir()) >= 8:
        raise HostUpgradeError("preflight retention bound reached; no evidence removed")
    root = own / secrets.token_hex(16)
    _directory(root, owner=0, group=user.pw_gid, mode=0o750, parent_owner=0, parent_modes={0o750})
    for name, source in control.sources.items():
        descriptor = os.open(
            root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            view = memoryview(source.payload)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise HostUpgradeError("preflight control copy made no progress")
                view = view[count:]
            os.fchown(descriptor, 0, user.pw_gid)
            os.fchmod(descriptor, 0o440)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    _copy_oci(bundle, root / "release.bundle", control.page.directives[-1].directive.release, user)
    tree.recheck()
    control.recheck()
    anchors._recheck_source(fragment)
    probe_unit = "umi-successor-preflight-" + root.name + ".service"
    home = _path(layout.logical_home(user.pw_dir) if layout else user.pw_dir)
    if Path("/var/lib") not in Path(home).parents:
        raise HostUpgradeError("preflight needs a dedicated service home beneath /var/lib")
    from .competition_host_service import _USER

    if not _USER.fullmatch(user.pw_name):
        raise HostUpgradeError("preflight service user is not literal")
    # Merge path lists into single D-Bus properties; a later duplicate property
    # would otherwise replace, rather than extend, the installed sandbox list.
    paths = {key: [] for key in ("ReadOnlyPaths", "ReadWritePaths")}
    keep = []
    for item in properties:
        key, _, value = item.partition("=")
        if key in paths:
            paths[key].extend(value.split())
        else:
            keep.append(item)

    def restricted(path):
        return ("+" if layout else "") + _path(path)

    paths["ReadOnlyPaths"].extend((restricted(tree.path), restricted(root)))
    paths["ReadWritePaths"].extend(
        (
            restricted(home),
            restricted(control.config.release_root),
            restricted(f"/run/user/{user.pw_uid}"),
        )
    )
    properties = keep + [key + "=" + " ".join(value) for key, value in paths.items()]
    properties += [
        "Type=oneshot",
        "User=" + user.pw_name,
        f"Group={user.pw_gid}",
        "ProtectHome=tmpfs",
        f"BindPaths=/run/user/{user.pw_uid}",
        "InaccessiblePaths=" + restricted(control.config.wallet.path),
        "Restart=no",
        "KillMode=mixed",
        "TimeoutStartSec=900s",
        "TimeoutStopSec=60s",
        "StandardOutput=journal",
        "StandardError=null",
        f"Requires=user@{user.pw_uid}.service",
        f"After=user@{user.pw_uid}.service",
    ]
    if layout:
        properties += [
            "RootDirectory=" + _path(layout.root_directory),
            "MountAPIVFS=yes",
            "Slice=umi-validators.slice",
            "BindReadOnlyPaths="
            + " ".join((_path(tree.path), _path(root), "/etc/resolv.conf:/etc/resolv.conf")),
        ]
    environment = [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONUNBUFFERED=1",
        "PYTHONUTF8=1",
        "HOME=" + home,
        "USER=" + (layout.runtime_user if layout else user.pw_name),
        "LOGNAME=" + (layout.runtime_user if layout else user.pw_name),
        f"XDG_RUNTIME_DIR=/run/user/{user.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{user.pw_uid}/bus",
    ]
    args = [
        "/usr/bin/systemd-run",
        "--quiet",
        "--wait",
        "--collect",
        "--unit=" + probe_unit,
        *("--property=" + value for value in properties),
        "--",
        "/usr/bin/env",
        "-i",
        *environment,
        str(tree.path / ".venv/bin/python"),
        "-I",
        "-B",
        "-m",
        "umi.competition_initial_upgrade",
        "rehearse",
        "--controls",
        str(root),
    ]
    try:
        result = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
            timeout=1000,
            check=False,
        )
    except BaseException:
        _systemctl("stop", probe_unit)
        raise
    if result.returncode:
        raise HostUpgradeError("wallet-free successor service rehearsal failed before stop")
    anchors._recheck_source(fragment)
    tree.recheck()
    control.recheck()


def _verify_rehearsal_host(control):
    from .competition_supervisor_cli import _running_executable_identity, _stable_file_identity

    root = _STAGE_PARENT / control.signed_host.manifest.umi_git_revision
    source = root / "src/umi/competition_initial_upgrade.py"
    interpreter = root / ".venv/bin/python"
    if (
        sys.platform != "linux"
        or os.geteuid() == 0
        or Path(__file__) != source
        or Path(sys.executable) != interpreter
        or Path(sys.prefix) != root / ".venv"
        or {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}.get(platform.machine())
        != control.config.target_platform
    ):
        raise HostUpgradeError("rehearsal is not running the exact signed host")
    ancestors = {path: _ancestor_identity(path) for path in _ancestor_paths(root)}
    source_identity = _stable_file_identity(source)
    interpreter_identity = _running_executable_identity(interpreter)
    fingerprints, _ = _read_tree(root, control.signed_host.manifest)
    if (
        fingerprints.get(source) != source_identity
        or fingerprints.get(interpreter) != interpreter_identity
    ):
        raise HostUpgradeError("rehearsal source or interpreter differs from the signed tree")
    if any(_ancestor_identity(path) != identity for path, identity in ancestors.items()):
        raise HostUpgradeError("rehearsal host parent changed")


async def _rehearse_child(controls: Path):
    from .competition_container import PodmanSuccessorContainer
    from .competition_supervisor_cli import _container_limits

    if os.geteuid() == 0:
        raise HostUpgradeError("rehearsal requires the installed non-root account")
    control = _controls(controls / activation.SOURCE_CONFIG_FILENAME, controls)
    print('{"status":"preflight","stage":"controls_verified"}', flush=True)
    _verify_rehearsal_host(control)
    print('{"status":"preflight","stage":"host_verified"}', flush=True)
    if os.stat(control.config.state_root).st_uid != os.geteuid():
        raise HostUpgradeError("rehearsal account differs from installed state")
    container = PodmanSuccessorContainer(control.config, limits=_container_limits())
    release = container.stage_release(
        controls / "release.bundle", control.page.directives[-1].directive.release
    )
    print('{"status":"preflight","stage":"release_staged"}', flush=True)
    await container.prepare_image(release)
    _verify_rehearsal_host(control)
    control.recheck()
    print('{"status":"preflight_passed","stage":"sandbox_verified"}', flush=True)


def main(argv=None):
    # Private fixed child entrypoint, never an arbitrary command runner.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["rehearse"])
    parser.add_argument("--controls", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        asyncio.run(_rehearse_child(args.controls))
    except (ValueError, OSError, RuntimeError, ValidatorSupervisorError):
        print('{"status":"preflight_failed"}', flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
