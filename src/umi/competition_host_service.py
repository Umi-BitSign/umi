"""Render the exact systemd successor override from verified installation inputs.

This is a non-mutating deployment plan. It does not stop a service, install a
drop-in, enable a user manager, release the old lock, or start the successor.
The privileged migration must perform and verify those steps separately.
"""

from __future__ import annotations

import hashlib
import pwd
import re
from dataclasses import dataclass
from pathlib import Path

from .competition_host_activation import ACTIVATION_MOUNT_ROOT
from .competition_host_anchor import MaterializedSuccessorAnchor
from .competition_host_artifacts import (
    SignedSuccessorHostArtifact,
    VerifiedHostTree,
    verify_host_artifact_authority,
)
from .competition_host_upgrade import StoppedSupervisor
from .competition_worker_cli import (
    WORKER_CHAIN_SPEC,
    WORKER_FINALITY_BINARY,
    WORKER_FINALITY_STATE_ROOT,
    WORKER_PROOF_BINARY,
    WORKER_RUNTIME_METADATA_BINARY,
)

_PATH = re.compile(r"^/[A-Za-z0-9_./-]+$")
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,63}$")


@dataclass(frozen=True, slots=True)
class SuccessorServiceSwitchPlan:
    unit_name: str
    service_uid: int
    service_user: str
    drop_in_path: Path
    drop_in_bytes: bytes
    drop_in_sha256: str
    cleanup_unit_name: str
    cleanup_unit_path: Path
    cleanup_unit_bytes: bytes
    cleanup_unit_sha256: str
    observer_state_source: Path
    required_user_manager: str
    source_parent_readonly_mount: Path
    host_manifest_sha256: str
    host_root: Path
    checkpoint_sha256: str


def _path(value: str | Path) -> str:
    value = str(value)
    path = Path(value)
    if not _PATH.fullmatch(value) or ".." in path.parts or value != str(path) or path == Path("/"):
        raise ValueError("service path is not a literal normalized systemd path")
    return value


def validate_host_service_resources(signed_host, observer):
    """Check the same helper pins and lifecycle tools before stop and publication.

    Signature and tree verification belong to the caller. This check grants no
    authority and performs no filesystem or service operations.
    """
    records = {item.path: item for item in signed_host.manifest.files}
    requirements = (
        (
            "artifacts/umi-grandpa-finality-observer",
            observer.finality_pin.release_sha256_by_target[observer.target_triple],
            0o555,
            WORKER_FINALITY_BINARY,
        ),
        (
            "artifacts/umi-substrate-proof-verifier",
            observer.proof_binary_sha256,
            0o555,
            WORKER_PROOF_BINARY,
        ),
        (
            "artifacts/raw_spec_finney.json",
            observer.finality_pin.chain_spec_sha256,
            0o444,
            WORKER_CHAIN_SPEC,
        ),
    )
    if getattr(observer, "runtime_metadata_binary", None) is not None:
        requirements += (
            (
                "artifacts/umi-runtime-metadata",
                observer.runtime_metadata_binary_sha256,
                0o555,
                WORKER_RUNTIME_METADATA_BINARY,
            ),
        )
    for name, sha, mode, _ in requirements:
        if name not in records or records[name].sha256 != sha or records[name].mode != mode:
            raise ValueError("host manifest lacks the exact installed observer resource")
    for entrypoint in ("umi-competition-supervisor", "umi-competition-supervisor-cleanup"):
        record = records.get(".venv/bin/" + entrypoint)
        if record is None or record.mode != 0o555:
            raise ValueError("host manifest lacks a fixed supervisor lifecycle entrypoint")
    return requirements


def plan_successor_service_switch(
    *,
    stopped: StoppedSupervisor,
    anchor: MaterializedSuccessorAnchor,
    host_tree: VerifiedHostTree,
    signed_host: SignedSuccessorHostArtifact,
) -> SuccessorServiceSwitchPlan:
    if (
        type(stopped) is not StoppedSupervisor
        or type(anchor) is not MaterializedSuccessorAnchor
        or type(host_tree) is not VerifiedHostTree
    ):
        raise TypeError("service switch planning requires genuine verified capabilities")
    stopped.recheck_stopped()
    anchor.recheck()
    host_tree.recheck()
    config = anchor.config
    verify_host_artifact_authority(
        signed_host, config=config, expected_manifest_sha256=anchor.receipt.host_manifest_sha256
    )
    if (
        stopped.config_sha256 != anchor.receipt.source_config_sha256
        or stopped.installation_sha256 != anchor.receipt.legacy_installation_sha256
        or stopped.service_uid != anchor.service_uid
        or stopped.validator_hotkey != config.validator_hotkey
        or host_tree.manifest_sha256 != anchor.receipt.host_manifest_sha256
        or host_tree.umi_git_revision != anchor.receipt.host_umi_git_revision
        or host_tree.target_platform != config.target_platform
        or signed_host.manifest.umi_git_revision != host_tree.umi_git_revision
        or signed_host.manifest.target_platform != config.target_platform
    ):
        raise ValueError("service switch inputs describe different installations")
    result = _plan_from_anchor(
        unit_name=stopped.unit_name,
        config_path=stopped._lease.config_path,
        anchor=anchor,
        host_tree=host_tree,
        signed_host=signed_host,
    )
    stopped.recheck_stopped()
    return result


def _plan_from_anchor(
    *,
    unit_name: str,
    config_path: Path,
    anchor: MaterializedSuccessorAnchor,
    host_tree: VerifiedHostTree,
    signed_host: SignedSuccessorHostArtifact,
) -> SuccessorServiceSwitchPlan:
    """Render for a verified anchor, including a retained switch after restart.

    This grants no stopped-host or chain authority. Callers must separately
    authenticate the exact unit, original lock and publication transaction.
    """
    from .competition_host_upgrade import _UNIT_RE, _service_layout

    if type(anchor) is not MaterializedSuccessorAnchor or type(host_tree) is not VerifiedHostTree:
        raise TypeError("service rendering requires genuine verified anchor and host tree")
    if not _UNIT_RE.fullmatch(unit_name):
        raise ValueError("service rendering requires a fixed supervisor unit name")
    layout = _service_layout(unit_name)
    anchor.recheck()
    host_tree.recheck()
    config = anchor.config
    verify_host_artifact_authority(
        signed_host, config=config, expected_manifest_sha256=anchor.receipt.host_manifest_sha256
    )
    if (
        host_tree.manifest_sha256 != anchor.receipt.host_manifest_sha256
        or host_tree.umi_git_revision != anchor.receipt.host_umi_git_revision
        or host_tree.target_platform != config.target_platform
        or signed_host.manifest.umi_git_revision != host_tree.umi_git_revision
        or signed_host.manifest.target_platform != config.target_platform
    ):
        raise ValueError("service rendering inputs describe different host releases")
    service_uid = anchor.service_uid
    user = pwd.getpwuid(service_uid)
    if not _USER.fullmatch(user.pw_name) or user.pw_uid != service_uid:
        raise ValueError("service account is not a fixed local non-root identity")
    _path(user.pw_dir)
    if Path("/var/lib") not in Path(user.pw_dir).parents:
        raise ValueError("successor service requires its dedicated home beneath /var/lib")
    if layout and user.pw_name != layout.service_user:
        raise ValueError("successor service account differs from its coordinator instance")
    home = layout.logical_home(user.pw_dir) if layout else Path(user.pw_dir)
    runtime_user = layout.runtime_user if layout else user.pw_name
    bind_source = layout.bind_source if layout else lambda path: path

    def restricted(path):
        return ("+" if layout else "") + _path(path)

    revision_root = host_tree.path
    source = anchor.source_root
    observer_source = Path(config.state_root) / "successor-observer"
    # Host and container see identical authenticated helper paths/config bytes,
    # but their writable observer databases are different physical directories.
    requirements = validate_host_service_resources(signed_host, anchor.observer_config.chain)
    env = (
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONUNBUFFERED=1",
        "PYTHONUTF8=1",
        "HOME=" + _path(home),
        "USER=" + runtime_user,
        "LOGNAME=" + runtime_user,
        f"XDG_RUNTIME_DIR=/run/user/{service_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{service_uid}/bus",
    )
    command = "/usr/bin/env -i " + " ".join(env) + " "
    manager = f"user@{service_uid}.service"
    cleanup_unit = unit_name.removesuffix(".service") + "-successor-cleanup.service"
    cleanup_command = (
        command
        + _path(revision_root / ".venv/bin/umi-competition-supervisor-cleanup")
        + " --config "
        + _path(config_path)
    )
    # This companion has no activation BindPaths or inherited main-unit sandbox.
    # It must be able to run when those paths prevent ExecStopPost from starting.
    cleanup_payload = (
        "\n".join(
            [
                "# Fixed wallet-free cleanup for one UMI successor installation.",
                "[Unit]",
                "Description=UMI successor failed-service cleanup",
                "Requires=" + manager,
                "After=" + manager,
                "[Service]",
                "Type=oneshot",
                "User=" + user.pw_name,
                "UMask=0077",
                "WorkingDirectory=/",
                "ExecStart=" + cleanup_command,
                "TimeoutStartSec=180s",
                "KillMode=mixed",
                "Restart=no",
                *(
                    [
                        "RootDirectory=" + _path(layout.root_directory),
                        "Slice=umi-validators.slice",
                        "MountAPIVFS=yes",
                        "ProtectHome=tmpfs",
                        f"BindPaths=/run/user/{service_uid}",
                        "BindReadOnlyPaths=" + _path(revision_root),
                        "InaccessiblePaths=+" + _path(config.wallet.path),
                    ]
                    if layout
                    else []
                ),
            ]
        )
        + "\n"
    ).encode()
    lines = [
        "# Generated from verified successor installation inputs.",
        "[Unit]",
        "Requires=" + manager,
        "After=" + manager,
        "OnFailure=",
        "OnFailure=" + cleanup_unit,
        "OnFailureJobMode=replace",
        "[Service]",
        "ExecStartPre=",
        "ExecStart=",
        "ExecStart="
        + command
        + _path(revision_root / ".venv/bin/umi-competition-supervisor")
        + " --config "
        + _path(config_path),
        "ExecStopPost=",
        # Ordinary stop cleanup. '+' does not bypass explicit BindPaths on
        # systemd 255: namespace setup failure needs a separate cleanup unit.
        # Drop to the exact service user; cleanup refuses root and takes the lock.
        "ExecStopPost=+/usr/sbin/runuser -u "
        + runtime_user
        + " -- "
        + command
        + _path(revision_root / ".venv/bin/umi-competition-supervisor-cleanup")
        + " --config "
        + _path(config_path),
        # ProtectHome=true makes /run/user inaccessible even with ReadWritePaths.
        # Keep other homes/runtime directories hidden; expose only our user bus.
        "ProtectHome=tmpfs",
        f"BindPaths=/run/user/{service_uid}",
        # Bind the parent, never the current directory inode being exchanged.
        "BindReadOnlyPaths=" + _path(bind_source(source)) + ":" + _path(ACTIVATION_MOUNT_ROOT),
        "BindPaths="
        + _path(bind_source(observer_source))
        + ":"
        + _path(WORKER_FINALITY_STATE_ROOT),
        "ReadWritePaths=" + restricted(observer_source),
        "ReadWritePaths=" + restricted(home) + " " + restricted(f"/run/user/{service_uid}"),
        "ReadOnlyPaths=" + restricted(revision_root),
    ]
    if layout:
        # systemd's manager is outside the upgrade process's private view.
        # Keep execution paths identical inside the original RootDirectory.
        lines += [
            "RootDirectory=" + _path(layout.root_directory),
            "Slice=umi-validators.slice",
            "BindReadOnlyPaths=" + _path(revision_root),
        ]
    for name, _, _, target in requirements:
        lines.append("BindReadOnlyPaths=" + _path(revision_root / name) + ":" + _path(target))
    payload = ("\n".join(lines) + "\n").encode()
    anchor.recheck()
    host_tree.recheck()
    return SuccessorServiceSwitchPlan(
        unit_name=unit_name,
        service_uid=service_uid,
        service_user=user.pw_name,
        drop_in_path=Path("/etc/systemd/system") / (unit_name + ".d") / "50-umi-successor.conf",
        drop_in_bytes=payload,
        drop_in_sha256=hashlib.sha256(payload).hexdigest(),
        cleanup_unit_name=cleanup_unit,
        cleanup_unit_path=Path("/etc/systemd/system") / cleanup_unit,
        cleanup_unit_bytes=cleanup_payload,
        cleanup_unit_sha256=hashlib.sha256(cleanup_payload).hexdigest(),
        observer_state_source=observer_source,
        required_user_manager=manager,
        source_parent_readonly_mount=source,
        host_manifest_sha256=host_tree.manifest_sha256,
        host_root=revision_root,
        checkpoint_sha256=anchor.receipt.checkpoint_sha256,
    )
