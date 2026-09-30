"""Persist the migration hold and drain the authenticated predecessor service.

This is the first root-owned step of evidence migration. It requires a genuine
certified replacement, preserves the original controls, and leaves a persistent
hold across failures. Its completion record grants no stopped-migration lease;
preparation and sealing must recheck the native locks and current chain proof.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import stat
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from .competition_chain_state import OwnedCompetitionChainObservation
from .competition_coordinator_namespace import ensure_coordinator_host_view
from .competition_evidence_activation import _private_transaction_root, _root_control
from .competition_evidence_prepare import _write_control
from .competition_evidence_resume import _service_command
from .competition_evidence_rollover import EligibleEvidenceRollover
from .competition_evidence_service import _held, evidence_service_guard, evidence_service_hold
from .competition_evidence_stopped import _stopped_unit
from .competition_history_compatibility import (
    validate_consent_transition,
    verify_history_compatibility,
)
from .competition_host_activation import SIGNED_HOST_ARTIFACT_FILENAME
from .competition_host_anchor import load_materialized_successor_anchor
from .competition_host_artifacts import (
    SignedSuccessorHostArtifact,
    VerifiedHostTree,
    parse_signed_host_artifact,
    verify_host_artifact_authority,
    verify_staged_host_tree,
)
from .competition_host_service import (
    SuccessorServiceSwitchPlan,
    _path,
    _plan_from_anchor,
    validate_host_service_resources,
)
from .competition_host_start import _exec_start_command, _process_owns_exact_lock
from .competition_host_switch import _cleanup_unit, _reload_systemd, _root_directory
from .competition_host_upgrade import (
    _check_service_namespace,
    _expected_cgroup,
    _require_root_linux,
    _unit_snapshot,
)
from .competition_supervisor import SuccessorSupervisorOperatorConsent
from .competition_switch_recovery import (
    INTENT_FILENAME,
    RETAINED_DIRECTORY,
    exclusive_upgrade_operation,
)
from .competition_upgrade import _open_without_links, _Reader
from .protocol import canonical_json_bytes


@dataclass(frozen=True)
class EvidenceDrainRequest:
    config_path: Path
    unit_name: str
    transaction_root: Path
    target_host_manifest_sha256: str


def _seal_control(path: Path, body: bytes) -> None:
    """Recover a private interrupted write before sealing its exact bytes."""
    parent = _root_directory(path.parent)
    try:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            _write_control(parent, path.name, body)
        else:
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) not in {0o600, 0o444}
                    or info.st_size != len(body)
                    or os.read(fd, len(body) + 1) != body
                ):
                    raise ValueError("evidence hold control differs from the retained intent")
            finally:
                os.close(fd)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            os.fchmod(fd, 0o444)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
        if _root_control(path) != body:
            raise ValueError("evidence hold control failed sealed readback")
    finally:
        os.close(parent)


def _controls(runtime: SuccessorServiceSwitchPlan, request: EvidenceDrainRequest) -> None:
    guard, _ = evidence_service_guard(request.unit_name, request.transaction_root)
    parent = _root_directory(runtime.drop_in_path.parent)
    try:
        allowed = {
            runtime.drop_in_path.name,
            guard.name,
            "." + guard.name + ".pending",
            INTENT_FILENAME,
            RETAINED_DIRECTORY,
        }
        if set(os.listdir(parent)) - allowed:
            raise ValueError("predecessor has unreviewed service overrides")
    finally:
        os.close(parent)
    for path, raw in (
        (runtime.drop_in_path, runtime.drop_in_bytes),
        (runtime.cleanup_unit_path, runtime.cleanup_unit_bytes),
    ):
        if _root_control(path) != raw:
            raise ValueError("predecessor runtime differs from its authenticated anchor")


def _unit(runtime: SuccessorServiceSwitchPlan, request: EvidenceDrainRequest) -> dict:
    values = _unit_snapshot(request.unit_name)
    layout = _check_service_namespace(request.unit_name, values)
    fragment = layout.fragment if layout else Path("/etc/systemd/system") / request.unit_name
    guard, _ = evidence_service_guard(request.unit_name, request.transaction_root)
    command = next(
        line.removeprefix("ExecStart=")
        for line in runtime.drop_in_bytes.decode().splitlines()
        if line.startswith("ExecStart=") and line != "ExecStart="
    )
    if (
        values["Id"] != request.unit_name
        or values["LoadState"] != "loaded"
        or values["User"] != runtime.service_user
        or values["FragmentPath"] != str(fragment)
        or values["DropInPaths"]
        not in {str(runtime.drop_in_path), f"{guard} {runtime.drop_in_path}"}
        or values["OnFailure"] != runtime.cleanup_unit_name
        or _exec_start_command(values["ExecStart"])
        != "{ path=/usr/bin/env ; argv[]=" + command + " ; ignore_errors=no"
    ):
        raise ValueError("loaded predecessor service differs from the installed runtime")
    return values


def _lock(path: Path, uid: int, *, expected: tuple[int, int] | None = None) -> int:
    fd = _open_without_links(path)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > 4096
        or (expected is not None and (info.st_dev, info.st_ino) != expected)
    ):
        os.close(fd)
        raise ValueError("predecessor supervisor process lock changed")
    return fd


async def _drain_locked(
    request: EvidenceDrainRequest,
    *,
    consent: SuccessorSupervisorOperatorConsent,
    eligible_replacement: EligibleEvidenceRollover,
    target_host_tree: VerifiedHostTree,
    target_signed_host: SignedSuccessorHostArtifact,
    observe_after_audit: Callable[[], Awaitable[OwnedCompetitionChainObservation]],
    timeout_seconds: int,
) -> dict:
    """Caller retains the root operator mutex through preparation and handoff."""
    if type(eligible_replacement) is not EligibleEvidenceRollover:
        raise ValueError("evidence drain requires a native certified replacement")
    root = _private_transaction_root(request.transaction_root)
    try:
        if set(os.listdir(root)) - {
            "drain-plan.json",
            ".drain-plan.json.pending",
            "HOLD",
            ".HOLD.pending",
            "drain-complete.json",
            ".drain-complete.json.pending",
        }:
            raise ValueError("evidence drain must resume through its current transaction phase")
        anchor = load_materialized_successor_anchor(request.config_path)
        grant = verify_history_compatibility(consent.history_compatibility, config=anchor.config)
        validate_consent_transition(consent, anchor.operator_consent, grant)
        if (
            grant.original_installation_receipt_sha256 != anchor.receipt_sha256
            or grant.target_host_manifest_sha256 != request.target_host_manifest_sha256
            or anchor.receipt.evidence_migration is not None
        ):
            raise ValueError("drain target differs from its original installation or consent")
        if type(target_host_tree) is not VerifiedHostTree:
            raise ValueError("evidence drain needs the verified staged replacement host")
        verify_host_artifact_authority(
            target_signed_host,
            config=anchor.config,
            expected_manifest_sha256=request.target_host_manifest_sha256,
        )
        target_host_tree.recheck()
        if (
            target_host_tree.manifest_sha256 != request.target_host_manifest_sha256
            or target_host_tree.umi_git_revision != target_signed_host.manifest.umi_git_revision
            or target_host_tree.target_platform != anchor.config.target_platform
        ):
            raise ValueError("staged replacement differs from the consented host")
        validate_host_service_resources(target_signed_host, anchor.observer_config.chain)
        reader = _Reader(0)
        signed = parse_signed_host_artifact(
            reader.file(
                anchor.anchor_path / SIGNED_HOST_ARTIFACT_FILENAME,
                "predecessor_host",
                32 * 1024**2,
                modes={0o444},
            )
        )
        tree = verify_staged_host_tree(
            signed,
            config=anchor.config,
            expected_manifest_sha256=anchor.receipt.host_manifest_sha256,
            stage_root=Path("/opt/umi-validator-supervisor-hosts")
            / anchor.receipt.host_umi_git_revision,
        )
        runtime = _plan_from_anchor(
            unit_name=request.unit_name,
            config_path=request.config_path,
            anchor=anchor,
            host_tree=tree,
            signed_host=signed,
        )
        _controls(runtime, request)
        unit = _unit(runtime, request)
        fragment = reader.file(
            Path(unit["FragmentPath"]),
            "unit_fragment",
            128 * 1024,
            modes={0o400, 0o444, 0o600, 0o644},
        )
        lock_path = Path(anchor.config.state_root) / "supervisor-process.lock"
        fd = _lock(lock_path, runtime.service_uid)
        try:
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
        finally:
            os.close(fd)
        if unit["ActiveState"] == "active":
            if (
                unit["SubState"] != "running"
                or unit["ControlPID"] != "0"
                or unit["ControlGroup"] != _expected_cgroup(request.unit_name)
            ):
                raise ValueError("predecessor process is not running in its installed cgroup")
            _process_owns_exact_lock(
                int(unit["MainPID"]),
                lock_path=lock_path,
                lock_identity=identity,
                service_uid=runtime.service_uid,
            )
        elif unit["ActiveState"] not in {"inactive", "failed", "deactivating"}:
            raise ValueError("predecessor is not ready for a bounded drain")
        _cleanup_unit(runtime, request.config_path)
        anchor.recheck()
        tree.recheck()
        audited_at = time.monotonic_ns()
        observation = await observe_after_audit()
        if observation.captured_monotonic_ns < audited_at:
            raise ValueError("evidence drain needs a fresh proof after its host audit")
        eligible_replacement.recheck(config=anchor.config, consent=consent, observation=observation)
        reader.unchanged()
        plan = canonical_json_bytes(
            {
                "schema": "umi-evidence-service-drain/1",
                "unit_name": request.unit_name,
                "config_path": str(request.config_path),
                "transaction_root": str(request.transaction_root),
                "source_config_sha256": hashlib.sha256(
                    canonical_json_bytes(anchor.config)
                ).hexdigest(),
                "original_receipt_sha256": anchor.receipt_sha256,
                "target_host_manifest_sha256": request.target_host_manifest_sha256,
                "fragment_sha256": hashlib.sha256(fragment).hexdigest(),
                "original_runtime_sha256": hashlib.sha256(runtime.drop_in_bytes).hexdigest(),
                "original_cleanup_sha256": hashlib.sha256(runtime.cleanup_unit_bytes).hexdigest(),
                "lock_path": str(lock_path),
                "lock_device": str(identity[0]),
                "lock_inode": str(identity[1]),
                "chain_submission_authorized": False,
            }
        )
        _write_control(root, "drain-plan.json", plan)
        guard, guard_bytes = evidence_service_guard(request.unit_name, request.transaction_root)
        _seal_control(
            request.transaction_root / "HOLD",
            evidence_service_hold(request.unit_name, request.target_host_manifest_sha256),
        )
        _seal_control(guard, guard_bytes)
        _reload_systemd()
        _held(request.unit_name, request.transaction_root, request.target_host_manifest_sha256)
        _controls(runtime, request)
        _unit(runtime, request)
        _cleanup_unit(runtime, request.config_path)
        reader.unchanged()
        target_host_tree.recheck()
        eligible_replacement.recheck(config=anchor.config, consent=consent, observation=observation)
        _service_command("stop", request.unit_name, timeout_seconds)
        _stopped_unit(request.unit_name, runtime.service_uid)
        _service_command("start", runtime.cleanup_unit_name, timeout_seconds)
        _cleanup_unit(runtime, request.config_path)
        _controls(runtime, request)
        _unit(runtime, request)
        _stopped_unit(request.unit_name, runtime.service_uid)
        _held(request.unit_name, request.transaction_root, request.target_host_manifest_sha256)
        reader.unchanged()
        fd = _lock(lock_path, runtime.service_uid, expected=identity)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = {
                "schema": "umi-evidence-service-drain-complete/1",
                "drain_plan_sha256": hashlib.sha256(plan).hexdigest(),
                "service_stopped": True,
                "hold_released": False,
                "chain_submission_authorized": False,
            }
            _write_control(root, "drain-complete.json", canonical_json_bytes(result))
        finally:
            os.close(fd)
        return result
    finally:
        os.close(root)


def drain_evidence_predecessor(
    request: EvidenceDrainRequest,
    *,
    consent: SuccessorSupervisorOperatorConsent,
    eligible_replacement: EligibleEvidenceRollover,
    target_host_tree: VerifiedHostTree,
    target_signed_host: SignedSuccessorHostArtifact,
    observe_after_audit: Callable[[], Awaitable[OwnedCompetitionChainObservation]],
    timeout_seconds: int = 3600,
) -> dict:
    """Stop or resume an exact predecessor; leave the hold for native migration."""
    _require_root_linux()
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 12600:
        raise ValueError("invalid evidence drain timeout")
    _path(request.config_path)
    evidence_service_guard(request.unit_name, request.transaction_root)
    ensure_coordinator_host_view(unit_name=request.unit_name, config_path=request.config_path)
    with exclusive_upgrade_operation(request.unit_name):
        return asyncio.run(
            _drain_locked(
                request,
                consent=consent,
                eligible_replacement=eligible_replacement,
                target_host_tree=target_host_tree,
                target_signed_host=target_signed_host,
                observe_after_audit=observe_after_audit,
                timeout_seconds=timeout_seconds,
            )
        )
