"""Authenticated broker launch into a private, non-signing replay namespace.

Root retains the authentic staging lease until bubblewrap and its PID namespace
have exited. The child receives only immutable controls, native executables,
untrusted portable proof files and its own writable history/provider stores.
No original journal, startup lock, weight approval or wallet is mounted.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import signal
import stat
import subprocess
import time
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_chain_resources import CompetitionChainResources
from .competition_host_activation import _root_owner_uid
from .competition_remote_proof_store import ProofArchiveStores
from .competition_reward_boot import MAX_BOOT_BYTES
from .competition_reward_history_preparation import (
    HistoryPreparationError,
    StandingHistoryPreparationLease,
    _control,
    _private_directory,
    _root_ancestors,
    validate_history_preparation_lease,
)
from .competition_reward_history_workers import HistoryVerificationProfile
from .open_competition import digest
from .private_files import Directory, private_path
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_LOG = logging.getLogger("umi.competition.progress")
WORK = Path("/run/umi-history-preparation")
PASSWD_PATH = Path("/etc/passwd")


class HistoryPreparationLaunch(StrictProtocolModel):
    schema_: Literal["umi-history-preparation-launch/1"] = Field(alias="schema")
    preparation_approval_sha256: Hex32
    source_root: Directory
    source_tree_sha256: Hex32
    python_root: Directory
    resources: CompetitionChainResources
    input_archive: Directory
    proof_stores: ProofArchiveStores | None = None
    verification_profile: HistoryVerificationProfile | None = None
    rpc_transport: Directory | None = None
    rpc_transport_sha256: Hex32 | None = None
    through_block: Annotated[int, Field(strict=True, ge=0, lt=2**53)] | None = None

    @model_validator(mode="after")
    def complete_transport_selection(self):
        if (self.rpc_transport is None) != (self.rpc_transport_sha256 is None):
            raise ValueError("explicit RPC transport needs its exact control identity")
        return self


def _transport_mounts(selected, uid):
    if selected.rpc_transport is None:
        return []
    path = Path(selected.rpc_transport)
    private_path(str(path))
    info = path.lstat()
    if (
        path.name != "transport.json"
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {_root_owner_uid(), uid}
        or info.st_mode & 0o022
        or info.st_nlink != 1
        or not 0 < info.st_size <= 64 * 1024
    ):
        raise HistoryPreparationError("selected RPC transport control differs")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != selected.rpc_transport_sha256:
        raise HistoryPreparationError("selected RPC transport bytes changed")
    value = json.loads(raw)
    if (
        set(value) != {"schema", "routes"}
        or value["schema"] != "umi-rpc-transport/1"
        or not isinstance(value["routes"], list)
        or not 1 <= len(value["routes"]) <= 16
    ):
        raise HistoryPreparationError("selected RPC transport schema differs")
    paths = [path]
    for route in value["routes"]:
        if set(route) != {"source", "endpoint", "authorization_file"}:
            raise HistoryPreparationError("selected RPC route shape differs")
        name = route["authorization_file"]
        if name is not None:
            if (
                type(name) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name) is None
            ):
                raise HistoryPreparationError("selected RPC credential name differs")
            credential = path.parent / name
            private_path(str(credential))
            details = credential.lstat()
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != uid
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or not 0 < details.st_size <= 4096
            ):
                raise HistoryPreparationError("selected RPC credential owner differs")
            paths.append(credential)
    # No credential body is read by the broker, printed or copied.
    return [(str(path), str(path)) for path in dict.fromkeys(paths)]


def preparation_source_identity(root: Path) -> str:
    """Bind a small root-sealed code tree, never a model or evidence payload."""
    _root_ancestors(root)
    records = []
    for path in sorted((root / "src" / "umi").rglob("*")):
        private_path(str(path))
        info = path.lstat()
        if (
            info.st_uid != _root_owner_uid()
            or info.st_mode & 0o022
            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
        ):
            raise HistoryPreparationError("preparation source tree is not root sealed")
        if path.is_file():
            if info.st_nlink != 1 or info.st_size > 16 * 1024**2:
                raise HistoryPreparationError("unexpected preparation source artifact")
            records.append(
                [str(path.relative_to(root)), hashlib.sha256(path.read_bytes()).hexdigest()]
            )
    if not records:
        raise HistoryPreparationError("preparation source tree is empty")
    return digest(records)


def _readonly_source(path: Path, *, directory=False):
    private_path(str(path))
    info = path.lstat()
    if (
        info.st_uid != _root_owner_uid()
        or info.st_mode & 0o022
        or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    ):
        raise HistoryPreparationError("preparation executable input is not root controlled")


def _account_metadata_mounts(uid: int, gid: int):
    # Path.home() is used during native dependency imports even though no
    # wallet or home directory is available. Supply the real read-only account
    # database, not a synthetic HOME or access to any account's home contents.
    _readonly_source(PASSWD_PATH)
    info = PASSWD_PATH.lstat()
    if info.st_nlink != 1 or not 0 < info.st_size <= 1024 * 1024:
        raise HistoryPreparationError("preparation account metadata differs")
    accounts = [
        fields
        for line in PASSWD_PATH.read_text().splitlines()
        if len(fields := line.split(":")) == 7 and fields[2] == str(uid)
    ]
    if (
        len(accounts) != 1
        or not accounts[0][0]
        or accounts[0][3] != str(gid)
        or not accounts[0][5].startswith("/")
        or "\x00" in accounts[0][5]
    ):
        raise HistoryPreparationError("preparation account metadata does not match service")
    return [(str(PASSWD_PATH), "/etc/passwd")]


def preparation_command(
    lease: StandingHistoryPreparationLease,
    *,
    launch_path: Path,
    standing_boot: Path,
    action: Literal["readiness", "replay"] = "replay",
) -> tuple[list[str], HistoryPreparationLaunch]:
    """Construct a fixed native command only under genuine staging ownership."""
    validate_history_preparation_lease(lease)
    if action not in {"readiness", "replay"}:
        raise HistoryPreparationError("unsupported native preparation action")
    raw, _ = _control(launch_path, 64 * 1024)
    selected = HistoryPreparationLaunch.model_validate_json(raw)
    if canonical_json_bytes(selected) != raw or (
        selected.preparation_approval_sha256 != digest(lease.approval)
    ):
        raise HistoryPreparationError("launcher differs from authenticated staging approval")
    target = (
        lease.approval.through_block if selected.through_block is None else selected.through_block
    )
    if not lease.first_block <= target <= lease.approval.through_block:
        raise HistoryPreparationError("launch work target exceeds authenticated preparation scope")
    boot_raw, _ = _control(standing_boot, MAX_BOOT_BYTES)
    if hashlib.sha256(boot_raw).hexdigest() != lease.approval.standing_boot_raw_sha256:
        raise HistoryPreparationError("launcher selected another standing boot")
    root = Path(lease.approval.preparation_directory)
    work = root / "work"
    _private_directory(work, lease._anchor.service_uid, lease.approval.service_gid)
    if selected.resources.state_directory != str(WORK / "finality"):
        raise HistoryPreparationError("preparation finality state must be private")
    selected.resources.check(lease.config.chain)
    code, python_root = Path(selected.source_root), Path(selected.python_root)
    for path in (code, python_root):
        _readonly_source(path, directory=True)
    if preparation_source_identity(code) != selected.source_tree_sha256:
        raise HistoryPreparationError("preparation source tree changed")
    archive = Path(selected.input_archive)
    _private_directory(archive, lease._anchor.service_uid)
    # Only portable proof directories are allowed from existing service stores.
    # Refuse an accidental live owner root or database-bearing archive.
    portable_entries = {"objects", "history", "endpoint", "interval", "registration"}
    if any(path.name not in portable_entries for path in archive.iterdir()):
        raise HistoryPreparationError("portable input contains a live owner namespace")
    for protected in (
        Path(lease._anchor.config.state_root),
        Path(lease._anchor.config.wallet.path),
    ):
        if archive == protected or protected in archive.parents or archive in protected.parents:
            raise HistoryPreparationError("portable input overlaps protected owner state")
    mounts = [
        (str(code), str(code)),
        (str(python_root), str(python_root)),
        (str(standing_boot), "/boot.json"),
        (str(launch_path), "/launch.json"),
        (str(lease._controls[0][0]), "/approval.json"),
        (str(archive), "/proof-input"),
    ]
    mounts.extend(_account_metadata_mounts(lease._anchor.service_uid, lease.approval.service_gid))
    mounts.extend(_transport_mounts(selected, lease._anchor.service_uid))
    for field in CompetitionChainResources.model_fields:
        value = getattr(selected.resources, field)
        if field != "state_directory" and value is not None:
            path = Path(value)
            _readonly_source(path)
            mounts.append((str(path), str(path)))
    # These are transport-only R2 credentials selected by root, never wallet
    # material. Keep each file at its exact selected path; do not expose /etc.
    if selected.proof_stores is not None:
        for path in selected.proof_stores.credential_paths():
            private_path(str(path))
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != lease._anchor.service_uid
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise HistoryPreparationError("R2 preparation credential owner differs")
            if Path(lease._anchor.config.wallet.path) in path.parents:
                raise HistoryPreparationError("preparation cannot expose a wallet")
            mounts.append((str(path), str(path)))
    directories = {Path("/etc"), Path("/run")}
    for _, destination in (
        *mounts,
        (str(work), str(WORK)),
        (str(lease.staged_history), str(lease.logical_history)),
    ):
        directories.update(p for p in Path(destination).parents if p != Path("/"))
    command = [
        "/usr/bin/bwrap",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ]
    for directory in sorted(directories, key=lambda p: (len(p.parts), str(p))):
        command += ["--perms", "0755", "--dir", str(directory)]
    for source, destination in (
        ("/usr", "/usr"),
        ("/lib", "/lib"),
        ("/lib64", "/lib64"),
        ("/etc/ssl", "/etc/ssl"),
        ("/etc/resolv.conf", "/etc/resolv.conf"),
        *mounts,
    ):
        command += ["--ro-bind", source, destination]
    if selected.rpc_transport is not None:
        command += ["--setenv", "UMI_RPC_TRANSPORT_CONFIG", selected.rpc_transport]
    command += [
        "--bind",
        str(work),
        str(WORK),
        "--bind",
        str(lease.staged_history),
        str(lease.logical_history),
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--perms",
        "1777",
        "--tmpfs",
        "/tmp",
        "--cap-add",
        "CAP_SETUID",
        "--cap-add",
        "CAP_SETGID",
        "--cap-add",
        "CAP_SETPCAP",
        "--chdir",
        "/",
        "--setenv",
        "PATH",
        "/usr/bin",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "/usr/bin/setpriv",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--reuid",
        str(lease._anchor.service_uid),
        "--regid",
        str(lease.approval.service_gid),
        "--clear-groups",
        "--no-new-privs",
        str(python_root / ".venv/bin/python"),
        "-I",
        "-S",
        "-B",
        "-u",
        "-c",
        "import sys;sys.path[:0]=[sys.argv[1],sys.argv[2]];"
        "from umi.competition_reward_history_preparation_worker import main;main()",
        str(code / "src"),
        str(python_root / ".venv/lib/python3.12/site-packages"),
        str(lease.logical_history),
        str(lease._anchor.service_uid),
        json.dumps(
            [
                lease.staged_history.stat().st_dev,
                lease.staged_history.stat().st_ino,
                lease._anchor.service_uid,
                lease.approval.service_gid,
            ]
        ),
        action,
        os.readlink("/proc/self/ns/mnt"),
        os.readlink("/proc/self/ns/pid"),
    ]
    lease.recheck()
    return command, selected


async def launch_history_preparation(
    lease,
    *,
    launch_path,
    standing_boot,
    stop: asyncio.Event,
    action: Literal["readiness", "replay"] = "replay",
):
    """Keep the authentic parent lease held throughout native child lifetime."""
    command, selected = preparation_command(
        lease, launch_path=launch_path, standing_boot=standing_boot, action=action
    )
    _, launch_identity = _control(launch_path, 64 * 1024)
    started = time.monotonic()
    last_report = 0.0
    child = subprocess.Popen(
        command, close_fds=True, start_new_session=True, env={"PATH": "/usr/bin", "LANG": "C.UTF-8"}
    )
    interrupted = False
    try:
        while child.poll() is None:
            lease.recheck()
            if _control(launch_path, 64 * 1024)[1] != launch_identity:
                raise HistoryPreparationError("sealed native launch selection changed")
            _transport_mounts(selected, lease._anchor.service_uid)
            if stop.is_set() and not interrupted:
                child.send_signal(signal.SIGTERM)
                interrupted = True
            if time.monotonic() - last_report >= 25 or (interrupted and last_report == 0):
                _LOG.info(
                    json.dumps(
                        {
                            "stage": "history_preparation_parent",
                            "state": "stopping" if interrupted else "running",
                            "elapsed_seconds": time.monotonic() - started,
                            "eta_seconds": None,
                            "eta_basis": "native_child_progress",
                            "child_pid": child.pid,
                            "weight_authority": False,
                        },
                        separators=(",", ":"),
                    )
                )
                last_report = time.monotonic()
            await asyncio.sleep(1)
        lease.recheck()
        return child.returncode
    finally:
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
            # Hold ownership even during cancellation; bubblewrap's PID owner
            # must exit before another preparation can acquire this same root.
            while child.poll() is None:
                try:
                    await asyncio.sleep(0.1)
                except asyncio.CancelledError:
                    continue
        child.wait()
