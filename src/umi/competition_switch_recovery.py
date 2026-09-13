"""Resume exact systemd file publication from a root-owned switch intent.

The explicit resume-start operation starts only the recorded successor. Neither
operation restores state or mints legacy recovery authority. Successor startup
must still reconcile its retained worker state.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_host_activation import SIGNED_HOST_ARTIFACT_FILENAME
from .competition_host_anchor import (
    MaterializedSuccessorAnchor,
    _rename_noreplace,
    load_materialized_successor_anchor,
)
from .competition_host_artifacts import (
    VerifiedHostTree,
    parse_signed_host_artifact,
    verify_staged_host_tree,
)
from .competition_host_service import SuccessorServiceSwitchPlan, _plan_from_anchor
from .competition_host_upgrade import (
    _UNIT_RE,
    HostUpgradeError,
    _check_service_namespace,
    _require_empty_cgroup,
    _require_root_linux,
    _service_layout,
    _unit_snapshot,
)
from .competition_upgrade import _fingerprint, _open_without_links, _Reader
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import (
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    ValidatorSupervisorError,
    parse_canonical_supervisor_directive_state,
)
from .validator_supervisor_runtime import DIRECTIVE_STATE_FILENAME

INTENT_FILENAME = "umi-switch-intent.json"
RETAINED_DIRECTORY = "retained-partials"
MAX_INTENT_BYTES = 128 * 1024
_PARTIAL = re.compile(r"^\.umi-successor-[0-9a-f]{32}$")
_SYSTEMD_ROOT = Path("/etc/systemd/system")
_UPGRADE_LOCK_ROOT = Path("/run/umi-successor-upgrades")
_RECOVERED: dict[int, tuple[object, str]] = {}


@dataclass(frozen=True, slots=True)
class RecoveredSuccessorServiceSwitch:
    """Start-only handle issued by verified recovery, with no legacy authority."""

    plan: SuccessorServiceSwitchPlan
    config_path: Path
    lock_path: Path
    lock_identity: tuple[int, ...]
    _anchor: MaterializedSuccessorAnchor = field(repr=False, compare=False)
    _tree: VerifiedHostTree = field(repr=False, compare=False)
    _unit: tuple[tuple[str, str], ...] = field(repr=False, compare=False)
    _cleanup_unit: tuple[tuple[str, str], ...] = field(repr=False, compare=False)
    _intent: bytes = field(repr=False, compare=False)
    _reader: _Reader = field(repr=False, compare=False)
    _history_reader: _Reader = field(repr=False, compare=False)


def _recovered_binding(result: RecoveredSuccessorServiceSwitch) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "plan": _plan_sha256(result.plan),
                "config": str(result.config_path),
                "lock": str(result.lock_path),
                "lock_identity": [str(value) for value in result.lock_identity],
                "unit": list(result._unit),
                "cleanup_unit": list(result._cleanup_unit),
                "intent": hashlib.sha256(result._intent).hexdigest(),
                "anchor": result._anchor.receipt_sha256,
                "tree": result._tree.manifest_sha256,
            }
        )
    ).hexdigest()


def _root_owner_uid() -> int:
    return 0


def _control_reader() -> _Reader:
    return _Reader(_root_owner_uid())


@contextmanager
def exclusive_upgrade_operation(unit_name: str):
    """Serialize operator operations across the writer-lock handoff and cleanup.

    The initial upgrade driver must hold this same lock across preparation,
    publication and start. This mutex is not an authorization or a writer lock.
    Its empty inode is retained after release; removing it could split waiters
    between two locks. Different validator units have independent mutexes.
    """
    from .competition_host_switch import _root_directory

    _require_root_linux()
    if not _UNIT_RE.fullmatch(unit_name):
        raise HostUpgradeError("invalid recovery unit")
    outer = _root_directory(_UPGRADE_LOCK_ROOT.parent)
    parent = descriptor = -1
    try:
        with suppress(FileExistsError):
            os.mkdir(_UPGRADE_LOCK_ROOT.name, 0o700, dir_fd=outer)
        parent = _root_directory(_UPGRADE_LOCK_ROOT)
        info = os.fstat(parent)
        if info.st_uid != _root_owner_uid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise HostUpgradeError("upgrade mutex directory is not private and root-owned")
        name = unit_name + ".lock"
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        initial = os.fstat(descriptor)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_uid != _root_owner_uid()
            or stat.S_IMODE(initial.st_mode) != 0o600
            or initial.st_nlink != 1
            or initial.st_size != 0
        ):
            raise HostUpgradeError("upgrade mutex is not an empty private root-owned file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostUpgradeError("another upgrade operation holds this validator") from None

        def recheck():
            current = _root_directory(_UPGRADE_LOCK_ROOT)
            try:
                observed = os.fstat(current)
                if (
                    (observed.st_dev, observed.st_ino) != (info.st_dev, info.st_ino)
                    or observed.st_uid != _root_owner_uid()
                    or stat.S_IMODE(observed.st_mode) != 0o700
                    or _fingerprint(os.stat(name, dir_fd=current, follow_symlinks=False))
                    != _fingerprint(initial)
                    or _fingerprint(os.fstat(descriptor)) != _fingerprint(initial)
                ):
                    raise HostUpgradeError("upgrade mutex changed during the operation")
            finally:
                os.close(current)

        recheck()
        yield
        recheck()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent >= 0:
            os.close(parent)
        os.close(outer)


class SuccessorSwitchIntent(StrictProtocolModel):
    schema_: Literal["umi-successor-service-switch-intent/1"] = Field(alias="schema")
    unit_name: Annotated[str, Field(max_length=100)]
    config_path: Annotated[str, Field(max_length=4096)]
    service_uid: Annotated[int, Field(gt=0)]
    config_sha256: Hex32
    installation_sha256: Hex32
    anchor_receipt_sha256: Hex32
    host_manifest_sha256: Hex32
    plan_sha256: Hex32
    fragment_sha256: Hex32
    original_unit: dict[str, Annotated[str, Field(max_length=32768)]]
    lock_device: Annotated[str, Field(pattern=r"^[0-9]{1,24}$")]
    lock_inode: Annotated[str, Field(pattern=r"^[0-9]{1,24}$")]
    service_started: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


def _plan_sha256(plan: SuccessorServiceSwitchPlan) -> str:
    values = {
        name: value.hex() if isinstance(value := getattr(plan, name), bytes) else str(value)
        for name in plan.__dataclass_fields__
    }
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()


def _parse(payload: bytes) -> SuccessorSwitchIntent:
    if not 0 < len(payload) <= MAX_INTENT_BYTES:
        raise HostUpgradeError("switch intent is missing or oversized")
    intent = SuccessorSwitchIntent.model_validate_json(payload)
    if canonical_json_bytes(intent) != payload or not _UNIT_RE.fullmatch(intent.unit_name):
        raise HostUpgradeError("switch intent is noncanonical or has an invalid unit")
    return intent


def _intent_bytes(stopped, anchor, plan) -> bytes:
    stopped.recheck_stopped()
    anchor.recheck()
    fragment = stopped._lease.reader.file(
        Path(stopped._lease.unit_snapshot["FragmentPath"]),
        "switch_fragment",
        128 * 1024,
        modes={0o400, 0o444, 0o600, 0o644},
        root_owned=True,
    )
    body = SuccessorSwitchIntent(
        schema="umi-successor-service-switch-intent/1",
        unit_name=plan.unit_name,
        config_path=str(stopped._lease.config_path),
        service_uid=stopped.service_uid,
        config_sha256=stopped.config_sha256,
        installation_sha256=stopped.installation_sha256,
        anchor_receipt_sha256=anchor.receipt_sha256,
        host_manifest_sha256=plan.host_manifest_sha256,
        plan_sha256=_plan_sha256(plan),
        fragment_sha256=hashlib.sha256(fragment).hexdigest(),
        original_unit=stopped._lease.unit_snapshot,
        lock_device=str(stopped._lease.lock_identity[0]),
        lock_inode=str(stopped._lease.lock_identity[1]),
    )
    payload = canonical_json_bytes(body)
    _parse(payload)
    return payload


def publish_switch_intent(plan: SuccessorServiceSwitchPlan, payload: bytes) -> int:
    """Atomically publish the fence and complete intent before companion files.

    A crash leaves either an inert staging directory or the complete intent in
    the fixed drop-in directory. Neither case loses a published switch's inputs.
    """
    from .competition_host_switch import _root_directory

    _require_root_linux()
    intent = _parse(payload)
    if intent.unit_name != plan.unit_name or intent.plan_sha256 != _plan_sha256(plan):
        raise HostUpgradeError("switch intent differs from its verified plan")
    parent = _root_directory(plan.drop_in_path.parent.parent)
    stage_fd = -1
    try:
        prefix = (
            ".umi-switch-stage-" + hashlib.sha256(plan.unit_name.encode()).hexdigest()[:16] + "-"
        )
        if sum(name.startswith(prefix) for name in os.listdir(parent)) >= 8:
            raise HostUpgradeError("retained switch intent staging slots exhausted")
        stage = prefix + secrets.token_hex(16)
        os.mkdir(stage, 0o700, dir_fd=parent)
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        file = os.open(
            INTENT_FILENAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=stage_fd,
        )
        try:
            remaining = memoryview(payload)
            while remaining:
                count = os.write(file, remaining)
                if count <= 0:
                    raise HostUpgradeError("switch intent write made no progress")
                remaining = remaining[count:]
            os.fchmod(file, 0o444)
            os.fsync(file)
        finally:
            os.close(file)
        os.fchmod(stage_fd, 0o755)
        os.fsync(stage_fd)
        _rename_noreplace(parent, stage, plan.drop_in_path.parent.name)
        os.fsync(parent)
        published = _root_directory(plan.drop_in_path.parent)
        try:
            if (os.fstat(published).st_dev, os.fstat(published).st_ino) != (
                os.fstat(stage_fd).st_dev,
                os.fstat(stage_fd).st_ino,
            ):
                raise HostUpgradeError("published switch intent directory changed")
        finally:
            os.close(published)
        result, stage_fd = stage_fd, -1
        return result
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        os.close(parent)


def read_switch_intent(plan: SuccessorServiceSwitchPlan) -> bytes:
    from .competition_host_switch import _root_directory

    parent = _root_directory(plan.drop_in_path.parent)
    os.close(parent)
    payload = _control_reader().file(
        plan.drop_in_path.parent / INTENT_FILENAME, "switch_intent", MAX_INTENT_BYTES, modes={0o444}
    )
    intent = _parse(payload)
    if intent.unit_name != plan.unit_name or intent.plan_sha256 != _plan_sha256(plan):
        raise HostUpgradeError("retained switch intent differs from its verified plan")
    return payload


def _retain_partial_files(plan, marker):
    """Preserve only bounded unfinished drop-in files; never interpret them."""
    from .competition_host_switch import _check_switch_marker, _root_directory

    _check_switch_marker(plan, marker)
    names = os.listdir(marker)
    if len(names) > 18:
        raise HostUpgradeError("too many retained switch files")
    for name in names:
        if name in {INTENT_FILENAME, plan.drop_in_path.name, RETAINED_DIRECTORY}:
            continue
        if not _PARTIAL.fullmatch(name):
            raise HostUpgradeError("unexpected retained switch file")
        info = os.stat(name, dir_fd=marker, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != _root_owner_uid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in {0o600, 0o444}
            or info.st_size > 128 * 1024
        ):
            raise HostUpgradeError("unsafe retained switch partial")
        try:
            os.mkdir(RETAINED_DIRECTORY, 0o700, dir_fd=marker)
            os.fsync(marker)
        except FileExistsError:
            pass
        retained = _root_directory(plan.drop_in_path.parent / RETAINED_DIRECTORY)
        try:
            if len(os.listdir(retained)) >= 16:
                raise HostUpgradeError("retained switch partial slots exhausted")
            _rename_noreplace(marker, name, name, destination_parent=retained)
            os.fsync(retained)
            os.fsync(marker)
        finally:
            os.close(retained)
    _check_switch_marker(plan, marker)


def _check_unit_identity(values, intent, plan, *, require_switched=False):
    original = intent.original_unit
    layout = _check_service_namespace(plan.unit_name, values)
    fragment = layout.fragment if layout else _SYSTEMD_ROOT / plan.unit_name
    if (
        values.get("Id") != plan.unit_name
        or values.get("LoadState") != "loaded"
        or values.get("User") != plan.service_user
        or values.get("FragmentPath") != str(fragment)
    ):
        raise HostUpgradeError("recovery unit does not match its fixed identity")
    for key in ("Id", "LoadState", "User", "FragmentPath", "RootDirectory", "RootImage", "Slice"):
        if values.get(key) != original.get(key):
            raise HostUpgradeError("recovery unit identity differs from the retained switch")
    if (
        values["ActiveState"] not in {"inactive", "failed"}
        or values["SubState"] not in {"dead", "failed"}
        or values["MainPID"] != "0"
        or values["ControlPID"] != "0"
    ):
        raise HostUpgradeError("recovery requires the exact stopped host-namespace service")
    _require_empty_cgroup(plan.unit_name, values["ControlGroup"])
    loaded = values["DropInPaths"] == str(plan.drop_in_path)
    if loaded:
        command = (
            str(plan.host_root)
            + "/.venv/bin/umi-competition-supervisor --config "
            + intent.config_path
            + " ;"
        )
        if command not in values["ExecStart"] or values.get("OnFailure") != plan.cleanup_unit_name:
            raise HostUpgradeError("recovery loaded an unexpected successor command")
    elif (
        require_switched
        or values["DropInPaths"]
        or values["ExecStart"] != original["ExecStart"]
        or values.get("OnFailure", "") != original.get("OnFailure", "")
    ):
        raise HostUpgradeError("recovery loaded an unexpected legacy command or override")


def recover_successor_service_switch(
    *, config_path: Path, unit_name: str
) -> RecoveredSuccessorServiceSwitch:
    """Finish an interrupted source publication; leave the exact service stopped.

    No state backups are restored, and no stopped legacy capability is issued.
    Running services, replaced locks, modified controls or changed v3 history
    cause a hold. Existing v4 state is neither read as authority nor overwritten.
    """
    from . import competition_host_switch as switch

    _require_root_linux()
    if not _UNIT_RE.fullmatch(unit_name):
        raise HostUpgradeError("invalid recovery unit")
    marker_path = _SYSTEMD_ROOT / (unit_name + ".d")
    # Reject an override which daemon-reload could discover after our preflight.
    pending_override = Path("/run/systemd/system") / (unit_name + ".d")
    try:
        pending_override.lstat()
    except FileNotFoundError:
        pass
    else:
        raise HostUpgradeError("recovery has an unreviewed runtime unit override")
    marker = switch._root_directory(marker_path)
    descriptor = -1
    try:
        reader = _control_reader()
        payload = reader.file(
            marker_path / INTENT_FILENAME, "switch_intent", MAX_INTENT_BYTES, modes={0o444}
        )
        intent = _parse(payload)
        if intent.unit_name != unit_name or intent.config_path != str(config_path):
            raise HostUpgradeError("recovery intent belongs to another installation")
        anchor = load_materialized_successor_anchor(config_path)
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
        plan = _plan_from_anchor(
            unit_name=unit_name,
            config_path=config_path,
            anchor=anchor,
            host_tree=tree,
            signed_host=signed,
        )
        if (
            intent.config_sha256 != anchor.receipt.source_config_sha256
            or intent.installation_sha256 != anchor.receipt.legacy_installation_sha256
            or intent.anchor_receipt_sha256 != anchor.receipt_sha256
            or intent.service_uid != anchor.service_uid
            or intent.host_manifest_sha256 != tree.manifest_sha256
            or intent.plan_sha256 != _plan_sha256(plan)
        ):
            raise HostUpgradeError("recovery anchor or host differs from the retained switch")
        layout = _service_layout(unit_name)
        fragment = layout.fragment if layout else _SYSTEMD_ROOT / unit_name
        if intent.original_unit.get("FragmentPath") != str(fragment):
            raise HostUpgradeError("retained switch names another unit fragment")
        reader.file(
            fragment,
            "unit_fragment",
            128 * 1024,
            modes={0o400, 0o444, 0o600, 0o644},
            expected_sha256=intent.fragment_sha256,
        )
        lock_path = Path(anchor.config.state_root) / "supervisor-process.lock"
        descriptor = _open_without_links(lock_path)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != intent.service_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 4096
            or (str(info.st_dev), str(info.st_ino)) != (intent.lock_device, intent.lock_inode)
        ):
            raise HostUpgradeError("recovery process lock was replaced or is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostUpgradeError("recovery process lock is still held") from None
        history_reader = _Reader(intent.service_uid)
        state = parse_canonical_supervisor_directive_state(
            history_reader.file(
                Path(anchor.config.state_root) / DIRECTIVE_STATE_FILENAME,
                "legacy_highwater",
                MAX_SUPERVISOR_DOCUMENT_BYTES,
                modes={0o600},
            ),
            trust_policy=anchor.config.trust_policy(),
        )
        if state != anchor.v3_state:
            raise HostUpgradeError("legacy history changed after the retained switch")
        before = _unit_snapshot(unit_name)
        _check_unit_identity(before, intent, plan)
        switch._check_switch_marker(plan, marker)
        _retain_partial_files(plan, marker)
        for path, body, digest, write in (
            (
                plan.cleanup_unit_path,
                plan.cleanup_unit_bytes,
                plan.cleanup_unit_sha256,
                lambda: switch._write_cleanup_once(plan),
            ),
            (
                plan.drop_in_path,
                plan.drop_in_bytes,
                plan.drop_in_sha256,
                lambda: switch._write_drop_in_once(plan, marker),
            ),
        ):
            try:
                path.lstat()
            except FileNotFoundError:
                write()
            switch._read_control(path, body, digest)
        reader.unchanged()
        history_reader.unchanged()
        anchor.recheck()
        tree.recheck()
        current = _unit_snapshot(unit_name)
        if current != before:
            # As in the initial switch, systemd may load the newly completed
            # drop-in while showing an inactive unit, before daemon-reload.
            # Only the exact sealed successor is an allowed transition here.
            switch._read_drop_in(plan)
            _check_unit_identity(current, intent, plan, require_switched=True)
        switch._reload_systemd()
        unit = _unit_snapshot(unit_name)
        _check_unit_identity(unit, intent, plan, require_switched=True)
        cleanup = switch._cleanup_unit(plan, config_path)
        switch._read_drop_in(plan)
        if read_switch_intent(plan) != payload:
            raise HostUpgradeError("retained intent changed during recovery")
        reader.unchanged()
        history_reader.unchanged()
        anchor.recheck()
        tree.recheck()
        named = _open_without_links(lock_path)
        try:
            if _fingerprint(os.fstat(named)) != _fingerprint(info):
                raise HostUpgradeError("process lock changed during recovery")
        finally:
            os.close(named)
        result = RecoveredSuccessorServiceSwitch(
            plan,
            config_path,
            lock_path,
            _fingerprint(info),
            anchor,
            tree,
            tuple(sorted(unit.items())),
            tuple(sorted(cleanup.items())),
            payload,
            reader,
            history_reader,
        )
        _RECOVERED[id(result)] = (result, _recovered_binding(result))
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(marker)


def recheck_recovered_successor_switch(result: RecoveredSuccessorServiceSwitch) -> None:
    """Recheck a start-only handle after its recovery lock has been released."""
    from . import competition_host_switch as switch

    _require_root_linux()
    issued = _RECOVERED.get(id(result))
    if (
        type(result) is not RecoveredSuccessorServiceSwitch
        or issued is None
        or issued[0] is not result
        or issued[1] != _recovered_binding(result)
    ):
        raise HostUpgradeError("successor switch was not recovered by this process")
    result._reader.unchanged()
    result._history_reader.unchanged()
    result._anchor.recheck()
    result._tree.recheck()
    switch._read_drop_in(result.plan)
    if read_switch_intent(result.plan) != result._intent:
        raise HostUpgradeError("recovered switch intent changed before start")
    descriptor = _open_without_links(result.lock_path)
    try:
        if _fingerprint(os.fstat(descriptor)) != result.lock_identity:
            raise HostUpgradeError("recovered switch process lock changed before start")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostUpgradeError("recovered switch process lock is still held") from None
        unit = _unit_snapshot(result.plan.unit_name)
        _check_unit_identity(unit, _parse(result._intent), result.plan, require_switched=True)
        if tuple(sorted(unit.items())) != result._unit:
            raise HostUpgradeError("recovered successor unit changed before start")
        cleanup = switch._cleanup_unit(result.plan, result.config_path)
        if tuple(sorted(cleanup.items())) != result._cleanup_unit:
            raise HostUpgradeError("recovered cleanup unit changed before start")
    finally:
        os.close(descriptor)


def resume_successor_service_publication(*, config_path: Path, unit_name: str) -> dict:
    from .competition_coordinator_namespace import ensure_coordinator_host_view

    ensure_coordinator_host_view(unit_name=unit_name, config_path=config_path)
    with exclusive_upgrade_operation(unit_name):
        result = recover_successor_service_switch(config_path=config_path, unit_name=unit_name)
    # A JSON status cannot be reused as a start capability.
    _RECOVERED.pop(id(result), None)
    return {
        "status": "source_switch_recovered",
        "unit_name": unit_name,
        "host_manifest_sha256": result.plan.host_manifest_sha256,
        "service_started": False,
        "chain_submission_authorized": False,
    }


def resume_and_start_successor_service(*, config_path: Path, unit_name: str) -> dict:
    from .competition_coordinator_namespace import ensure_coordinator_host_view
    from .competition_host_start import start_committed_successor_service

    ensure_coordinator_host_view(unit_name=unit_name, config_path=config_path)
    with exclusive_upgrade_operation(unit_name):
        result = recover_successor_service_switch(config_path=config_path, unit_name=unit_name)
        try:
            started = start_committed_successor_service(result)
        finally:
            _RECOVERED.pop(id(result), None)
    return {
        "status": "successor_service_running",
        "unit_name": started.unit_name,
        "main_pid": started.main_pid,
        "host_manifest_sha256": started.host_manifest_sha256,
        "checkpoint_sha256": started.checkpoint_sha256,
        "service_started": True,
        "chain_submission_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initial = commands.add_parser(
        "upgrade", help="rehearse, stop, archive, switch and start one legacy service"
    )
    initial.add_argument("--config", type=Path, required=True)
    initial.add_argument("--unit", required=True)
    initial.add_argument("--controls", type=Path, required=True)
    initial.add_argument("--host-bundle", type=Path, required=True)
    initial.add_argument("--oci-bundle", type=Path, required=True)
    initial.add_argument("--recovery-root", type=Path, required=True)
    initial.add_argument("--recovery-limits", type=Path, required=True)
    initial.add_argument("--historical-context", type=Path)
    for command, help_text in (
        ("resume-publication", "recover verified files; keep service stopped"),
        ("resume-start", "recover and start only the exact retained successor switch"),
    ):
        resume = commands.add_parser(command, help=help_text)
        resume.add_argument("--config", type=Path, required=True)
        resume.add_argument("--unit", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "upgrade":
            from .competition_initial_upgrade import upgrade_successor_service

            result = upgrade_successor_service(
                config_path=args.config,
                unit_name=args.unit,
                controls_path=args.controls,
                host_bundle=args.host_bundle,
                oci_bundle=args.oci_bundle,
                recovery_root=args.recovery_root,
                recovery_limits_path=args.recovery_limits,
                historical_context_path=args.historical_context,
            )
        else:
            operation = (
                resume_and_start_successor_service
                if args.command == "resume-start"
                else resume_successor_service_publication
            )
            result = operation(config_path=args.config, unit_name=args.unit)
    except (
        ValueError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        ValidatorSupervisorError,
    ):
        print(
            json.dumps(
                {
                    "status": "held",
                    "reason_code": "initial_host_upgrade_failed"
                    if args.command == "upgrade"
                    else "host_switch_recovery_failed",
                    "service_started": None
                    if args.command in {"upgrade", "resume-start"}
                    else False,
                    "service_state": "unconfirmed"
                    if args.command in {"upgrade", "resume-start"}
                    else "unchanged",
                    "chain_submission_authorized": False,
                }
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
