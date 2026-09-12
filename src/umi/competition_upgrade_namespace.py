"""Private, process-lifetime mounts for the stopped-host chain observer.

Call once from a fresh, single-threaded Linux upgrade process. All mounts are
made after unsharing and disabling propagation. The caller stays in that
namespace until it exits; no host-wide mount is installed or removed. Existing
validator data is never used as the temporary finality cache.
"""

from __future__ import annotations

import ctypes
import os
import stat
from pathlib import Path

from .competition_host_artifacts import VerifiedHostTree
from .competition_host_observer import _same_mount
from .competition_host_switch import _root_directory
from .competition_host_upgrade import HostUpgradeError, _require_root_linux
from .competition_upgrade import _open_without_links
from .competition_worker_cli import (
    WORKER_CHAIN_SPEC,
    WORKER_FINALITY_BINARY,
    WORKER_FINALITY_STATE_ROOT,
    WORKER_PROOF_BINARY,
)
from .protocol import canonical_json_bytes
from .validator_supervisor import ValidatorSupervisorConfig

_CLONE_NEWNS = 0x00020000
_MS_RDONLY = 1
_MS_NOSUID = 2
_MS_NODEV = 4
_MS_NOEXEC = 8
_MS_REMOUNT = 32
_MS_BIND = 4096
_MS_REC = 16384
_MS_PRIVATE = 1 << 18
_BASES = (Path("/opt/umi"), Path("/var/lib/umi-competition"))
_ENTERED_PID: int | None = None


def _mount(source: str | None, target: str, filesystem: str | None, flags: int, data=None):
    # Linux mount(2). No shell, mount helper, network mount or user-supplied flags.
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.mount
    call.argtypes = (
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_char_p,
    )
    call.restype = ctypes.c_int
    arguments = tuple(
        None if item is None else os.fsencode(item) for item in (source, target, filesystem)
    )
    if call(*arguments, flags, None if data is None else os.fsencode(data)) != 0:
        raise HostUpgradeError("could not establish the private observer mount") from OSError(
            ctypes.get_errno(), "mount"
        )


def _namespace_id(path: str = "/proc/self/ns/mnt") -> tuple[int, int]:
    # These are kernel namespace handles, not caller-supplied filesystem paths.
    info = os.stat(path)
    return info.st_dev, info.st_ino


def _single_thread() -> None:
    with os.scandir("/proc/self/task") as tasks:
        if sum(1 for _ in tasks) != 1:
            raise HostUpgradeError("observer namespace requires a fresh single-threaded process")


def _unshare_mounts() -> None:
    global _ENTERED_PID
    _require_root_linux()
    _single_thread()
    if _ENTERED_PID is not None:
        raise HostUpgradeError("observer namespace preparation cannot be repeated or inherited")
    before = _namespace_id()
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.unshare
    call.argtypes = (ctypes.c_int,)
    call.restype = ctypes.c_int
    if call(_CLONE_NEWNS) != 0:
        raise HostUpgradeError("could not create a private observer namespace")
    # Mark immediately. Any later failure requires exiting this process, not a
    # retry that could mistake half-prepared mounts for an installed namespace.
    _ENTERED_PID = os.getpid()
    if _namespace_id() in {before, _namespace_id("/proc/1/ns/mnt")}:
        raise HostUpgradeError("observer mount namespace did not become private")
    _mount(None, "/", None, _MS_REC | _MS_PRIVATE)


def _identity(descriptor: int) -> tuple[int, int, int, int, int]:
    info = os.fstat(descriptor)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _fd_path(descriptor: int) -> str:
    return f"/proc/self/fd/{descriptor}"


def _source(path: Path, *, mode: int, directory: bool = False) -> int:
    parent = _root_directory(path.parent)
    os.close(parent)
    descriptor = _open_without_links(path)
    info = os.fstat(descriptor)
    if (
        not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != mode
        or (not directory and info.st_nlink != 1)
    ):
        os.close(descriptor)
        raise HostUpgradeError("observer namespace source has unsafe ownership, mode or type")
    return descriptor


def _ensure_base(path: Path) -> int:
    parent = _root_directory(path.parent)
    try:
        try:
            os.mkdir(path.name, mode=0o755, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        return _root_directory(path)
    finally:
        os.close(parent)


def _temporary_base(path: Path, descriptor: int) -> None:
    # The placeholder directory may persist on the host if newly created.
    # Contents and permissions of an existing base are never changed there.
    _mount(
        "tmpfs",
        _fd_path(descriptor),
        "tmpfs",
        _MS_NOSUID | _MS_NODEV,
        "size=65536,nr_inodes=16,mode=0755",
    )
    fresh = _root_directory(path)
    try:
        if _identity(fresh)[:2] == _identity(descriptor)[:2]:
            raise HostUpgradeError("private observer overlay was not installed at its fixed path")
    finally:
        os.close(fresh)


def _bind(source: int, target: Path, *, directory: bool) -> None:
    # Every target is on one of this process's private tmpfs mounts. Source
    # descriptors pin the verified inode across mount(2), including path races.
    parent = _root_directory(target.parent)
    target_fd = -1
    try:
        if directory:
            os.mkdir(target.name, mode=0o700, dir_fd=parent)
            target_fd = _open_without_links(target)
        else:
            target_fd = os.open(
                target.name,
                os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o400,
                dir_fd=parent,
            )
        _mount(_fd_path(source), _fd_path(target_fd), None, _MS_BIND)
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        os.close(parent)
    mounted = _open_without_links(target)
    try:
        if _identity(mounted) != _identity(source):
            raise HostUpgradeError("private observer bind changed its source inode")
        flags = _MS_REMOUNT | _MS_BIND | _MS_NOSUID | _MS_NODEV
        flags |= _MS_NOEXEC if directory else _MS_RDONLY
        _mount(None, _fd_path(mounted), None, flags)
    finally:
        os.close(mounted)


def prepare_upgrade_observer_namespace(
    *, host_tree: VerifiedHostTree, config: ValidatorSupervisorConfig, control_directory: Path
) -> None:
    """Mount signed helpers and a separate existing root-private finality cache.

    This establishes paths only. StoppedUpgradeObserver independently checks
    consent, the signed manifest, configuration hashes and stopped-host identity
    before executing a helper. No service is stopped or started by this call.
    """
    _require_root_linux()
    if type(host_tree) is not VerifiedHostTree:
        raise HostUpgradeError("observer namespace requires a verified signed host tree")
    host_tree.recheck()
    config = ValidatorSupervisorConfig.model_validate_json(canonical_json_bytes(config))
    if host_tree.target_platform != config.target_platform:
        raise HostUpgradeError("observer namespace host platform differs from its installation")
    if not control_directory.is_absolute() or control_directory != Path(
        os.path.normpath(control_directory)
    ):
        raise HostUpgradeError("observer controls need a canonical absolute path")
    control = _root_directory(control_directory)
    try:
        if stat.S_IMODE(os.fstat(control).st_mode) not in {0o700, 0o750}:
            raise HostUpgradeError("observer namespace controls are not private")
    finally:
        os.close(control)
    cache = control_directory / "finality-state"
    roots = (
        host_tree.path,
        control_directory,
        *(
            Path(value)
            for value in (
                config.state_root,
                config.worker_state_root,
                config.release_root,
                config.operator_input_root,
                config.wallet.path,
            )
        ),
    )
    for base in _BASES:
        if any(base == root or base in root.parents or root in base.parents for root in roots):
            raise HostUpgradeError("observer overlay overlaps a preserved installation root")
    for root in roots[2:]:
        if cache == root or cache in root.parents or root in cache.parents:
            raise HostUpgradeError("observer cache overlaps a preserved installation root")
    resources = (
        (host_tree.path / "artifacts/umi-grandpa-finality-observer", WORKER_FINALITY_BINARY, 0o555),
        (host_tree.path / "artifacts/umi-substrate-proof-verifier", WORKER_PROOF_BINARY, 0o555),
        (host_tree.path / "artifacts/raw_spec_finney.json", WORKER_CHAIN_SPEC, 0o444),
    )
    opened: list[int] = []
    try:
        for source, _, mode in resources:
            opened.append(_source(source, mode=mode))
        opened.append(_source(cache, mode=0o700, directory=True))
        host_tree.recheck()
        _unshare_mounts()
        # A descriptor opened before unshare retains its old vfsmount. Linux
        # rejects using that mount as a bind source in the new namespace.
        # Reopen in the private namespace while requiring the same inode and
        # access boundary; keep the old descriptor until the comparison passes.
        sources = (*((path, mode, False) for path, _, mode in resources), (cache, 0o700, True))
        for index, (path, mode, directory) in enumerate(sources):
            fresh = _source(path, mode=mode, directory=directory)
            if _identity(fresh) != _identity(opened[index]):
                os.close(fresh)
                raise HostUpgradeError("observer source changed across namespace creation")
            os.close(opened[index])
            opened[index] = fresh
        host_tree.recheck()
        for base in _BASES:
            descriptor = _ensure_base(base)
            try:
                _temporary_base(base, descriptor)
            finally:
                os.close(descriptor)
        Path("/opt/umi/bin").mkdir(mode=0o755)
        for descriptor, (_, target, _) in zip(opened, resources, strict=False):
            _bind(descriptor, target, directory=False)
        _bind(opened[-1], WORKER_FINALITY_STATE_ROOT, directory=True)
        for base in _BASES:
            descriptor = _root_directory(base)
            try:
                _mount(
                    None,
                    _fd_path(descriptor),
                    None,
                    _MS_REMOUNT | _MS_RDONLY | _MS_NOSUID | _MS_NODEV,
                )
            finally:
                os.close(descriptor)
        host_tree.recheck()
        for source, target, mode in resources:
            _same_mount(source, target, directory=False, mode=mode)
        _same_mount(cache, WORKER_FINALITY_STATE_ROOT, directory=True, mode=0o700)
    finally:
        for descriptor in opened:
            os.close(descriptor)
