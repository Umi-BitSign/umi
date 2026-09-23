"""Resume startup after a completed, root-sealed evidence runtime publication.

The persistent start intent precedes releasing the service hold. Recovery may
verify an already running selected process, or restart the same runtime. It
never rewrites journals, restores the old executable, signs, or submits weights.
The supervisor still verifies current authorization through its native path.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .competition_coordinator_namespace import ensure_coordinator_host_view
from .competition_evidence_activation import EvidenceActivationPlan, _receipt, _root_control
from .competition_evidence_prepare import _write_control
from .competition_evidence_service import (
    _activation_result,
    _loaded_conditions,
    _private_record,
    evidence_service_guard,
    evidence_service_hold,
)
from .competition_host_activation import SIGNED_HOST_ARTIFACT_FILENAME
from .competition_host_anchor import MaterializedSuccessorAnchor, load_materialized_successor_anchor
from .competition_host_artifacts import (
    VerifiedHostTree,
    parse_signed_host_artifact,
    verify_staged_host_tree,
)
from .competition_host_service import SuccessorServiceSwitchPlan, _path, _plan_from_anchor
from .competition_host_start import _exec_start_command, _process_owns_exact_lock, _StartupPending
from .competition_host_switch import _cleanup_unit, _reload_systemd, _root_directory
from .competition_host_upgrade import (
    HostUpgradeError,
    _check_service_namespace,
    _expected_cgroup,
    _require_empty_cgroup,
    _require_root_linux,
    _service_layout,
    _unit_snapshot,
)
from .competition_switch_recovery import (
    INTENT_FILENAME,
    RETAINED_DIRECTORY,
    exclusive_upgrade_operation,
)
from .competition_upgrade import _open_without_links, _Reader
from .protocol import canonical_json_bytes


@dataclass(frozen=True)
class _Selection:
    activation: EvidenceActivationPlan
    config_path: Path
    anchor: MaterializedSuccessorAnchor
    tree: VerifiedHostTree
    runtime: SuccessorServiceSwitchPlan
    publication: bytes
    identity: dict
    reader: _Reader

    @property
    def root(self) -> Path:
        return self.activation.transaction_root

    @property
    def lock_path(self) -> Path:
        return Path(self.identity["lock_path"])

    @property
    def lock_identity(self) -> tuple[int, int]:
        return int(self.identity["lock_device"]), int(self.identity["lock_inode"])


def _load(config_path: Path, unit: str, root: Path) -> _Selection:
    _path(root)
    raw = _private_record(root, "activation-plan.json")
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or value.pop("schema", None) != "umi-weight-evidence-activation-plan/1"
    ):
        raise ValueError("invalid evidence activation plan")
    for key in ("live_source", "prepared_source", "transaction_root"):
        value[key] = Path(_path(value[key]))
    plan = EvidenceActivationPlan(**value)
    if (
        plan.encoded() != raw
        or plan.transaction_root != root
        or plan.live_source == plan.prepared_source
        or plan.live_source.parent != plan.prepared_source.parent
        or root.is_relative_to(plan.live_source)
        or root.is_relative_to(plan.prepared_source)
    ):
        raise ValueError("evidence activation plan is not canonical or belongs elsewhere")
    if _private_record(root, "activation-complete.json") != canonical_json_bytes(
        _activation_result(plan)
    ):
        raise ValueError("evidence activation has not completed")
    anchor = load_materialized_successor_anchor(config_path)
    if (
        anchor.source_root != plan.live_source
        or anchor.receipt_sha256 != plan.candidate_receipt_sha256
        or _receipt(plan.prepared_source)[1] != plan.original_receipt_sha256
        or anchor.receipt.evidence_migration is None
        or anchor.receipt.evidence_migration.compatibility_sha256 != plan.compatibility_sha256
    ):
        raise ValueError("evidence recovery anchor differs from the committed exchange")
    reader = _Reader(0)
    signed = parse_signed_host_artifact(
        reader.file(
            anchor.anchor_path / SIGNED_HOST_ARTIFACT_FILENAME,
            "host_manifest",
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
        unit_name=unit, config_path=config_path, anchor=anchor, host_tree=tree, signed_host=signed
    )
    publication = _private_record(root, "service-publication.json")
    published = json.loads(publication)
    identity = published["original_service"]
    layout = _service_layout(unit)
    fragment = layout.fragment if layout else Path("/etc/systemd/system") / unit
    identity_keys = {
        "unit_name",
        "service_uid",
        "service_user",
        "fragment_path",
        "fragment_sha256",
        "lock_path",
        "lock_device",
        "lock_inode",
    }
    if (
        not isinstance(identity, dict)
        or set(identity) != identity_keys
        or identity["unit_name"] != unit
        or identity["service_uid"] != runtime.service_uid
        or identity["service_user"] != runtime.service_user
        or identity["fragment_path"] != str(fragment)
        or identity["lock_path"] != str(Path(anchor.config.state_root) / "supervisor-process.lock")
        or any(
            not isinstance(identity[k], str)
            or not identity[k].isascii()
            or not identity[k].isdigit()
            for k in ("lock_device", "lock_inode")
        )
    ):
        raise ValueError("retained evidence service identity differs from installation")
    reader.file(
        fragment,
        "unit_fragment",
        128 * 1024,
        modes={0o400, 0o444, 0o600, 0o644},
        expected_sha256=identity["fragment_sha256"],
    )
    controls = []
    for path, body, name in (
        (runtime.drop_in_path, runtime.drop_in_bytes, "original-supervisor.conf"),
        (runtime.cleanup_unit_path, runtime.cleanup_unit_bytes, "original-cleanup.service"),
    ):
        controls.append(
            {
                "path": str(path),
                "original_sha256": hashlib.sha256(_private_record(root, name)).hexdigest(),
                "selected_sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    intent = {
        "schema": "umi-evidence-service-selection/1",
        "activation_plan_sha256": hashlib.sha256(plan.encoded()).hexdigest(),
        "unit_name": unit,
        "host_manifest_sha256": runtime.host_manifest_sha256,
        "original_service": identity,
        "controls": controls,
    }
    if _private_record(root, "service-selection.json") != canonical_json_bytes(
        intent
    ) or publication != canonical_json_bytes(
        {
            **intent,
            "schema": "umi-evidence-service-publication/1",
            "service_started": False,
            "hold_released": False,
            "chain_submission_authorized": False,
        }
    ):
        raise ValueError("evidence service publication differs from retained selection")
    return _Selection(plan, config_path, anchor, tree, runtime, publication, identity, reader)


def _controls(selection: _Selection) -> None:
    r = selection.runtime
    guard, raw = evidence_service_guard(r.unit_name, selection.root)
    parent = _root_directory(r.drop_in_path.parent)
    try:
        names = set(os.listdir(parent))
        if not names <= {guard.name, r.drop_in_path.name, INTENT_FILENAME, RETAINED_DIRECTORY}:
            raise ValueError("evidence service has unexpected drop-in files")
        if INTENT_FILENAME in names:
            _root_control(r.drop_in_path.parent / INTENT_FILENAME, maximum=128 * 1024)
        if RETAINED_DIRECTORY in names:
            retained = _root_directory(r.drop_in_path.parent / RETAINED_DIRECTORY)
            os.close(retained)
    finally:
        os.close(parent)
    for path, body in (
        (guard, raw),
        (r.drop_in_path, r.drop_in_bytes),
        (r.cleanup_unit_path, r.cleanup_unit_bytes),
    ):
        if _root_control(path) != body:
            raise ValueError("selected evidence runtime control changed")
    if _private_record(selection.root, "service-publication.json") != selection.publication:
        raise ValueError("evidence service publication changed")
    selection.reader.unchanged()
    selection.anchor.recheck()
    selection.tree.recheck()


def _unit(selection: _Selection, *, selected: bool = True) -> dict:
    r = selection.runtime
    unit = _unit_snapshot(r.unit_name)
    _check_service_namespace(r.unit_name, unit)
    if (
        unit["Id"] != r.unit_name
        or unit["LoadState"] != "loaded"
        or unit["User"] != r.service_user
        or unit["FragmentPath"] != selection.identity["fragment_path"]
    ):
        raise ValueError("evidence service identity changed")
    if selected:
        guard, _ = evidence_service_guard(r.unit_name, selection.root)
        command = next(
            line.removeprefix("ExecStart=")
            for line in r.drop_in_bytes.decode().splitlines()
            if line.startswith("ExecStart=") and line != "ExecStart="
        )
        expected = "{ path=/usr/bin/env ; argv[]=" + command + " ; ignore_errors=no"
        if (
            unit["DropInPaths"] != f"{guard} {r.drop_in_path}"
            or unit["OnFailure"] != r.cleanup_unit_name
            or _exec_start_command(unit["ExecStart"]) != expected
        ):
            raise ValueError("loaded evidence runtime differs from its sealed controls")
        condition = ["ConditionPathExists", False, True, str(selection.root / "HOLD")]
        if not any(row[:4] == condition for row in _loaded_conditions(r.unit_name)):
            raise ValueError("evidence hold condition is not loaded")
    return unit


def _stopped(selection: _Selection, unit: dict) -> None:
    if (
        unit["ActiveState"] not in {"inactive", "failed"}
        or unit["SubState"] not in {"dead", "failed"}
        or unit["MainPID"] != "0"
        or unit["ControlPID"] != "0"
    ):
        raise ValueError("evidence recovery service is not stopped")
    _require_empty_cgroup(selection.runtime.unit_name, unit["ControlGroup"])


def _lock(selection: _Selection) -> int:
    fd = _open_without_links(selection.lock_path)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != selection.runtime.service_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 4096
            or (info.st_dev, info.st_ino) != selection.lock_identity
        ):
            raise ValueError("original evidence service process lock changed")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _hold_state(selection: _Selection) -> str:
    paths = [selection.root / name for name in ("HOLD", "HOLD.released")]
    found = []
    for path in paths:
        try:
            raw = _root_control(path)
        except FileNotFoundError:
            continue
        if raw != evidence_service_hold(
            selection.runtime.unit_name, selection.runtime.host_manifest_sha256
        ):
            raise ValueError("evidence service hold binding changed")
        found.append(path.name)
    if len(found) != 1:
        raise ValueError("evidence service needs exactly one retained hold marker")
    return found[0]


def _move_hold(selection: _Selection, *, release: bool) -> None:
    current = _hold_state(selection)
    desired = "HOLD.released" if release else "HOLD"
    if current == desired:
        return
    parent = _root_directory(selection.root)
    try:
        os.rename(current, desired, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _service_command(verb: str, unit: str, timeout: int) -> None:
    subprocess.run(
        ["/usr/bin/systemctl", verb, "--", unit],
        check=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )


def _running(selection: _Selection) -> int:
    unit = _unit(selection)
    if unit["ActiveState"] == "activating":
        raise _StartupPending("evidence service is activating")
    if (
        unit["ActiveState"] != "active"
        or unit["SubState"] != "running"
        or not unit["MainPID"].isascii()
        or not unit["MainPID"].isdigit()
        or int(unit["MainPID"]) <= 1
        or unit["ControlPID"] != "0"
        or unit["ControlGroup"] != _expected_cgroup(selection.runtime.unit_name)
    ):
        raise ValueError("selected evidence service is not running in its exact cgroup")
    pid = int(unit["MainPID"])
    _process_owns_exact_lock(
        pid,
        lock_path=selection.lock_path,
        lock_identity=selection.lock_identity,
        service_uid=selection.runtime.service_uid,
    )
    _controls(selection)
    if _unit(selection) != unit:
        raise _StartupPending("selected evidence process changed during verification")
    return pid


def _resume(selection: _Selection, timeout: int) -> dict:
    """Caller holds the cross-process upgrade mutex in the exact host view."""
    _controls(selection)
    intent = canonical_json_bytes(
        {
            "schema": "umi-evidence-service-start/1",
            "publication_sha256": hashlib.sha256(selection.publication).hexdigest(),
            "candidate_receipt_sha256": selection.activation.candidate_receipt_sha256,
            "unit_name": selection.runtime.unit_name,
            "chain_submission_authorized": False,
        }
    )
    hold = _hold_state(selection)
    if hold == "HOLD.released" and _private_record(selection.root, "service-start.json") != intent:
        raise ValueError("released evidence hold lacks its exact durable start intent")
    unit = _unit(selection, selected=False)
    if unit["ActiveState"] in {"active", "activating"}:
        if _private_record(selection.root, "service-start.json") != intent:
            raise ValueError("running evidence service lacks its exact durable start intent")
        _cleanup_unit(selection.runtime, selection.config_path)
        pid = _running(selection)
        # A prior failed-start containment may have restored the hold before
        # its stop failed. Resume only after verifying this exact running PID.
        _move_hold(selection, release=True)
    else:
        _stopped(selection, unit)
        fd = _lock(selection)
        try:
            _reload_systemd()
            _controls(selection)
            _stopped(selection, _unit(selection))
            _cleanup_unit(selection.runtime, selection.config_path)
            parent = _root_directory(selection.root)
            try:
                _write_control(parent, "service-start.json", intent)
            finally:
                os.close(parent)
            _service_command("start", selection.runtime.required_user_manager, timeout)
            _controls(selection)
            _stopped(selection, _unit(selection))
            _move_hold(selection, release=True)
        finally:
            os.close(fd)
        try:
            _service_command("start", selection.runtime.unit_name, timeout)
            deadline = time.monotonic() + timeout
            while True:
                try:
                    pid = _running(selection)
                    break
                except (_StartupPending, FileNotFoundError):
                    if time.monotonic() >= deadline:
                        raise HostUpgradeError("evidence startup verification timed out") from None
                    time.sleep(0.25)
        except BaseException:
            _move_hold(selection, release=False)
            _service_command("stop", selection.runtime.unit_name, timeout)
            _controls(selection)
            _cleanup_unit(selection.runtime, selection.config_path)
            _service_command("start", selection.runtime.cleanup_unit_name, timeout)
            _stopped(selection, _unit(selection))
            _cleanup_unit(selection.runtime, selection.config_path)
            raise
    result = {
        "schema": "umi-evidence-service-start-complete/1",
        "start_intent_sha256": hashlib.sha256(intent).hexdigest(),
        "unit_name": selection.runtime.unit_name,
        "host_manifest_sha256": selection.runtime.host_manifest_sha256,
        "service_started": True,
        "chain_submission_authorized": False,
    }
    parent = _root_directory(selection.root)
    try:
        _write_control(parent, "service-start-complete.json", canonical_json_bytes(result))
    finally:
        os.close(parent)
    return {**result, "main_pid": pid}


def resume_selected_evidence_service(
    *, config_path: Path, unit_name: str, transaction_root: Path, startup_timeout_seconds: int = 600
) -> dict:
    _require_root_linux()
    if type(startup_timeout_seconds) is not int or not 1 <= startup_timeout_seconds <= 3600:
        raise ValueError("evidence startup timeout must be between 1 and 3600 seconds")
    ensure_coordinator_host_view(unit_name=unit_name, config_path=config_path)
    with exclusive_upgrade_operation(unit_name):
        return _resume(_load(config_path, unit_name, transaction_root), startup_timeout_seconds)
