"""Publish a migrated supervisor's runtime controls under a durable service hold.

The caller installs the exact guard and hold before stopping the supervisor.
This module requires the native stopped lease and completed anchor exchange;
it never stops, reloads or starts services, releases the hold, or signs authority.
After the lease closes, the root driver must reload and verify the selected
runtime before releasing the hold and verifying startup.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

from .competition_evidence_activation import (
    EvidenceActivationPlan,
    _receipt,
    _root_control,
    _root_linux,
)
from .competition_evidence_prepare import _write_control
from .competition_evidence_stopped import StoppedEvidenceMigration
from .competition_host_anchor import load_materialized_successor_anchor
from .competition_host_artifacts import SignedSuccessorHostArtifact, VerifiedHostTree
from .competition_host_service import _path, _plan_from_anchor
from .competition_host_switch import _root_directory
from .competition_upgrade import _Reader
from .file_identity import file_fingerprint
from .protocol import canonical_json_bytes

_MAX_CONTROL = 16 * 1024


def _activation_result(plan: EvidenceActivationPlan) -> dict:
    return {
        "schema": "umi-weight-evidence-activation/1",
        "plan_sha256": hashlib.sha256(plan.encoded()).hexdigest(),
        "selected_receipt_sha256": plan.candidate_receipt_sha256,
        "retained_original_receipt_sha256": plan.original_receipt_sha256,
        "chain_submission_authorized": False,
        "service_started": False,
    }


def _root_owner_uid() -> int:
    return 0


def evidence_service_guard(unit_name: str, transaction_root: Path) -> tuple[Path, bytes]:
    """Render installer inputs; no service or authorization is changed."""
    from .competition_host_upgrade import _UNIT_RE

    if not _UNIT_RE.fullmatch(unit_name):
        raise ValueError("evidence service guard needs an exact validator unit")
    _path(transaction_root)
    if any(
        transaction_root.is_relative_to(root)
        for root in ("/run", "/tmp", "/var/tmp", "/dev", "/proc", "/sys")
    ):
        raise ValueError("evidence service hold needs persistent storage")
    guard = Path("/etc/systemd/system") / (unit_name + ".d") / "40-umi-evidence-hold.conf"
    raw = (
        f"[Unit]\nRequiresMountsFor={transaction_root}\n"
        f"ConditionPathExists=!{transaction_root / 'HOLD'}\n"
    ).encode()
    return guard, raw


def evidence_service_hold(unit_name: str, host_manifest_sha256: str) -> bytes:
    """Content of the root-sealed hold installed before stopping the old host."""
    return canonical_json_bytes(
        {
            "schema": "umi-evidence-service-hold/1",
            "unit_name": unit_name,
            "host_manifest_sha256": host_manifest_sha256,
        }
    )


def _private_record(root: Path, name: str) -> bytes:
    parent = _root_directory(root)
    descriptor = -1
    try:
        info = os.fstat(parent)
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("evidence service transaction must be private")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != _root_owner_uid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= _MAX_CONTROL
        ):
            raise ValueError("evidence service record is not private and root-owned")
        raw = os.read(descriptor, _MAX_CONTROL + 1)
        if len(raw) != before.st_size or file_fingerprint(before) != file_fingerprint(
            os.fstat(descriptor)
        ):
            raise ValueError("evidence service record changed")
        return raw
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _loaded_conditions(unit_name: str) -> list:
    label = "".join(
        chr(b) if chr(b).isascii() and chr(b).isalnum() else f"_{b:02x}" for b in unit_name.encode()
    )
    result = subprocess.run(
        [
            "/usr/bin/busctl",
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/" + label,
            "org.freedesktop.systemd1.Unit",
            "Conditions",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode or len(result.stdout) > 32 * 1024:
        raise ValueError("cannot verify loaded evidence service hold")
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or value.get("type") != "a(sbbsi)":
        raise ValueError("invalid loaded evidence service conditions")
    conditions = value.get("data")
    if not isinstance(conditions, list) or any(
        not isinstance(row, list)
        or len(row) != 5
        or type(row[0]) is not str
        or type(row[1]) is not bool
        or type(row[2]) is not bool
        or type(row[3]) is not str
        or type(row[4]) is not int
        for row in conditions
    ):
        raise ValueError("invalid loaded evidence service conditions")
    return conditions


def _held(unit_name: str, root: Path, host_sha256: str) -> None:
    guard, raw = evidence_service_guard(unit_name, root)
    if _root_control(guard) != raw or _root_control(root / "HOLD") != evidence_service_hold(
        unit_name, host_sha256
    ):
        raise ValueError("evidence service hold differs from selected migration")
    expected = ["ConditionPathExists", False, True, str(root / "HOLD")]
    if not any(row[:4] == expected for row in _loaded_conditions(unit_name)):
        raise ValueError("evidence service hold is not loaded by systemd")


def _replace_control(path: Path, *, old_sha256: str, new: bytes) -> None:
    """Replace only an exact old control; an interrupted identical retry is safe."""
    if not 0 < len(new) <= _MAX_CONTROL:
        raise ValueError("evidence service control exceeds bound")
    observed = _root_control(path, maximum=_MAX_CONTROL)
    if observed == new:
        return
    if hashlib.sha256(observed).hexdigest() != old_sha256:
        raise ValueError("evidence service control differs from retained original")
    parent = _root_directory(path.parent)
    descriptor = -1
    name = "." + path.name + ".evidence-pending"
    try:
        descriptor = os.open(
            name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != _root_owner_uid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in {0o600, 0o444}
            or info.st_size > len(new)
            or not new.startswith(os.read(descriptor, len(new) + 1))
        ):
            raise ValueError("interrupted evidence service control differs")
        os.ftruncate(descriptor, 0)
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(new)
            stream.flush()
            os.fchmod(descriptor, 0o444)
            os.fsync(descriptor)
        if _root_control(path, maximum=_MAX_CONTROL) != observed:
            raise ValueError("evidence service control changed before replacement")
        os.rename(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def publish_stopped_evidence_service(
    activation_plan: EvidenceActivationPlan,
    *,
    config_path: Path,
    unit_name: str,
    verified_host_tree: VerifiedHostTree,
    signed_host: SignedSuccessorHostArtifact,
    lease: StoppedEvidenceMigration,
) -> dict:
    """Select both runtime controls while the old loaded unit remains stopped.

    The global upgrade mutex must span the caller's entire hold/migration/start.
    The native lease is rechecked throughout. Do not reload systemd inside that
    lease: its exact original unit observation is intentionally still required.
    The durable hold survives a crash between the two file replacements.
    """
    _root_linux()
    if (
        type(lease) is not StoppedEvidenceMigration
        or type(verified_host_tree) is not VerifiedHostTree
    ):
        raise ValueError("evidence service publication needs native stopped and host capabilities")
    anchor = load_materialized_successor_anchor(config_path)
    lease.validate_scope(activation_plan, anchor.config)
    if unit_name != lease._unit or anchor.source_root != activation_plan.live_source:
        raise ValueError("evidence service publication scope differs from stopped migration")
    receipt, receipt_sha = _receipt(activation_plan.live_source)
    if receipt != anchor.receipt or receipt_sha != activation_plan.candidate_receipt_sha256:
        raise ValueError("evidence service anchor has not selected the sealed candidate")
    expected = _activation_result(activation_plan)
    root = activation_plan.transaction_root
    if _private_record(root, "activation-complete.json") != canonical_json_bytes(expected):
        raise ValueError("evidence service needs the completed exact anchor exchange")
    runtime = _plan_from_anchor(
        unit_name=unit_name,
        config_path=config_path,
        anchor=anchor,
        host_tree=verified_host_tree,
        signed_host=signed_host,
    )
    _held(unit_name, root, runtime.host_manifest_sha256)
    identity = lease.runtime_identity()
    reader = _Reader(_root_owner_uid())
    fragment = reader.file(
        Path(identity["fragment_path"]),
        "evidence_service_fragment",
        128 * 1024,
        modes={0o400, 0o444, 0o600, 0o644},
    )
    identity["fragment_sha256"] = hashlib.sha256(fragment).hexdigest()
    descriptor = _root_directory(root)
    try:
        selections = (
            (runtime.drop_in_path, runtime.drop_in_bytes, "original-supervisor.conf"),
            (runtime.cleanup_unit_path, runtime.cleanup_unit_bytes, "original-cleanup.service"),
        )
        # Preserve both originals before replacing either. Retry never records
        # already-replaced bytes as the original or silently changes the target.
        originals = []
        for path, _, retained_name in selections:
            try:
                old = _private_record(root, retained_name)
            except FileNotFoundError:
                old = _root_control(path, maximum=_MAX_CONTROL)
                _write_control(descriptor, retained_name, old)
            originals.append(hashlib.sha256(old).hexdigest())
        intent = {
            "schema": "umi-evidence-service-selection/1",
            "activation_plan_sha256": expected["plan_sha256"],
            "unit_name": unit_name,
            "host_manifest_sha256": runtime.host_manifest_sha256,
            "original_service": identity,
            "controls": [
                {
                    "path": str(path),
                    "original_sha256": old,
                    "selected_sha256": hashlib.sha256(raw).hexdigest(),
                }
                for (path, raw, _), old in zip(selections, originals, strict=True)
            ],
        }
        _write_control(descriptor, "service-selection.json", canonical_json_bytes(intent))
        for (path, raw, _), old in zip(selections, originals, strict=True):
            lease.validate_scope(activation_plan, anchor.config)
            _held(unit_name, root, runtime.host_manifest_sha256)
            _replace_control(path, old_sha256=old, new=raw)
        for path, raw, _ in selections:
            if _root_control(path, maximum=_MAX_CONTROL) != raw:
                raise ValueError("selected evidence service control readback differs")
        anchor.recheck()
        verified_host_tree.recheck()
        lease.validate_scope(activation_plan, anchor.config)
        _held(unit_name, root, runtime.host_manifest_sha256)
        reader.unchanged()
        result = {
            **intent,
            "schema": "umi-evidence-service-publication/1",
            "service_started": False,
            "hold_released": False,
            "chain_submission_authorized": False,
        }
        _write_control(descriptor, "service-publication.json", canonical_json_bytes(result))
        return result
    finally:
        os.close(descriptor)
