"""Private logical-path views of the coordinator's two validator roots.

This prepares filesystem access for a fresh root upgrade process, without
stopping a service or granting recovery authority. Signed config bytes and
state paths are unchanged. A systemd-launched child does not inherit this view;
its bind sources must use the physical host paths returned by the layout.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .competition_host_upgrade import HostUpgradeError, _require_root_linux
from .competition_upgrade import _open_without_links

_INSTANCE = re.compile(r"^umi-validator@(0|54)\.service$")
_ROOTS = (
    (Path("/etc/umi"), True),
    (Path("/opt/umi-validator-supervisor"), True),
    (Path("/var/lib/umi-validator-supervisor"), False),
    (Path("/var/lib/umi-validator-worker-state"), False),
    (Path("/var/lib/umi-validator-operator-inputs"), True),
    (Path("/var/lib/umi-validator-runtime-wallets"), True),
)
_ACTIVE: CoordinatorHostView | None = None


def _literal(path: Path) -> Path:
    value = str(path)
    if (
        not re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
        or value != str(Path(value))
        or ".." in Path(value).parts
        or Path(value) == Path("/")
    ):
        raise HostUpgradeError("coordinator path must be literal and absolute")
    return Path(value)


@dataclass(frozen=True, slots=True)
class CoordinatorLayout:
    """A path mapping, not an authentication or stopped-service capability."""

    unit_name: str

    def __post_init__(self):
        if not _INSTANCE.fullmatch(self.unit_name):
            raise HostUpgradeError("unsupported coordinator validator instance")

    @property
    def instance(self) -> str:
        return self.unit_name.partition("@")[2].removesuffix(".service")

    @property
    def root_directory(self) -> Path:
        return Path("/var/lib/umi-validator-hosts") / ("uid" + self.instance)

    @property
    def service_user(self) -> str:
        return "umi-validator-uid" + self.instance

    @property
    def service_home(self) -> Path:
        return Path("/var/lib/umi-validator-supervisor/home")

    @property
    def account_home(self) -> Path:
        return Path("/var/lib/umi-validator-supervisor")

    @property
    def runtime_user(self) -> str:
        return "umi-validator"

    @property
    def fragment(self) -> Path:
        return Path("/etc/systemd/system/umi-validator@.service")

    @property
    def cgroup(self) -> str:
        return "/umi.slice/umi-validators.slice/" + self.unit_name

    def physical(self, logical: Path) -> Path:
        """Translate only known preserved roots; reject cross-instance paths."""
        logical = _literal(logical)
        if logical == self.root_directory.parent or self.root_directory.parent in logical.parents:
            raise HostUpgradeError("physical coordinator path supplied as a logical path")
        if not any(logical == root or root in logical.parents for root, _ in _ROOTS):
            raise HostUpgradeError("logical path is outside the preserved coordinator roots")
        return self.root_directory / logical.relative_to("/")

    def bind_source(self, logical: Path) -> Path:
        """Translate legacy paths, leaving separately staged host controls alone."""
        logical = _literal(logical)
        if any(logical == root or root in logical.parents for root, _ in _ROOTS):
            return self.physical(logical)
        if logical == self.root_directory.parent or self.root_directory.parent in logical.parents:
            raise HostUpgradeError("bind source names an unreviewed physical validator path")
        return logical

    def logical_home(self, host_home: str) -> Path:
        if _literal(Path(host_home)) != self.physical(self.account_home):
            raise HostUpgradeError("coordinator account home differs from its instance")
        return self.service_home


def _identity(fd: int) -> tuple[int, ...]:
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def _source(path: Path, service_uid: int) -> int:
    from .competition_host_switch import _root_directory

    parent = _root_directory(path.parent)
    os.close(parent)
    fd = _open_without_links(path)
    info = os.fstat(fd)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, service_uid}
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        os.close(fd)
        raise HostUpgradeError("coordinator source has unsafe type, ownership or permissions")
    return fd


def _check_inner_account(layout: CoordinatorLayout, service_uid: int) -> None:
    from .competition_host_switch import _root_directory
    from .competition_host_upgrade import _root_file

    path = layout.root_directory / "etc/passwd"
    parent = _root_directory(path.parent)
    os.close(parent)
    _root_file(path)
    fd = _open_without_links(path)
    try:
        payload = os.read(fd, 65537)
        if len(payload) > 65536:
            raise HostUpgradeError("coordinator public account database exceeds its bound")
    finally:
        os.close(fd)
    rows = [line.split(":") for line in payload.decode("utf-8").splitlines()]
    selected = [
        row
        for row in rows
        if len(row) == 7 and (row[0] == layout.runtime_user or row[2] == str(service_uid))
    ]
    if len(selected) != 1 or (
        selected[0][0] != layout.runtime_user
        or selected[0][2] != str(service_uid)
        or selected[0][5] != str(layout.account_home)
    ):
        raise HostUpgradeError("coordinator inner account differs from its host service identity")


@dataclass(frozen=True, slots=True)
class CoordinatorHostView:
    layout: CoordinatorLayout
    service_uid: int
    pid: int
    namespace: tuple[int, int]
    identities: tuple[tuple[Path, tuple[int, ...]], ...]

    def recheck(self) -> None:
        from .competition_upgrade_namespace import _namespace_id

        if _ACTIVE is not self or self.pid != os.getpid() or self.namespace != _namespace_id():
            raise HostUpgradeError("coordinator view is not active in this process namespace")
        _check_inner_account(self.layout, self.service_uid)
        for logical, expected in self.identities:
            for path in (logical, self.layout.physical(logical)):
                fd = _source(path, self.service_uid)
                try:
                    if _identity(fd) != expected:
                        raise HostUpgradeError("coordinator view changed its preserved inode")
                finally:
                    os.close(fd)


def active_coordinator_view(unit_name: str | None = None) -> CoordinatorHostView | None:
    view = _ACTIVE
    if view is not None:
        view.recheck()
        if unit_name is not None and unit_name != view.layout.unit_name:
            raise HostUpgradeError("coordinator view belongs to another validator")
    return view


def ensure_coordinator_host_view(*, unit_name: str, config_path: Path) -> None:
    """Enter the exact instance view for an explicit initial/resume operation."""
    if not _INSTANCE.fullmatch(unit_name):
        # A generic operation must not accidentally inherit an instance view.
        active_coordinator_view(unit_name)
        return
    if config_path != Path("/etc/umi/validator-supervisor.json"):
        raise HostUpgradeError("coordinator upgrade requires the installed logical config path")
    _require_root_linux()
    if active_coordinator_view(unit_name) is not None:
        return
    import pwd

    layout = CoordinatorLayout(unit_name)
    try:
        user = pwd.getpwnam(layout.service_user)
    except KeyError:
        raise HostUpgradeError("coordinator service account is unavailable") from None
    layout.logical_home(user.pw_dir)
    prepare_coordinator_host_view(unit_name=unit_name, service_uid=user.pw_uid)


def prepare_coordinator_host_view(*, unit_name: str, service_uid: int) -> CoordinatorHostView:
    """Map one instance privately; call before threads and exit after any failure.

    The generic service adapter still rejects RootDirectory installations until
    its namespace-aware inspection/rendering path is selected. This function
    alone neither selects that path nor authorizes a service operation.
    """
    global _ACTIVE
    from .competition_host_switch import _root_directory
    from .competition_upgrade_namespace import (
        _MS_BIND,
        _MS_NODEV,
        _MS_NOSUID,
        _MS_RDONLY,
        _MS_REMOUNT,
        _ensure_base,
        _fd_path,
        _mount,
        _namespace_id,
        _unshare_mounts,
    )

    _require_root_linux()
    layout = CoordinatorLayout(unit_name)
    if type(service_uid) is not int or service_uid <= 0 or _ACTIVE is not None:
        raise HostUpgradeError("coordinator view needs one non-root service identity")
    root = _root_directory(layout.root_directory)
    os.close(root)
    _check_inner_account(layout, service_uid)
    descriptors: list[int] = []
    try:
        for logical, _ in _ROOTS:
            descriptors.append(_source(layout.physical(logical), service_uid))
        identities = tuple(
            (logical, _identity(fd)) for (logical, _), fd in zip(_ROOTS, descriptors, strict=True)
        )
        _unshare_mounts()
        for index, ((logical, readonly), (_, expected)) in enumerate(
            zip(_ROOTS, identities, strict=True)
        ):
            # Reopen in the new vfsmount namespace, retaining the same source
            # inode. An fd from before unshare cannot safely select this mount.
            fresh = _source(layout.physical(logical), service_uid)
            if _identity(fresh) != expected:
                os.close(fresh)
                raise HostUpgradeError("coordinator source changed across namespace creation")
            os.close(descriptors[index])
            descriptors[index] = fresh
            target = _ensure_base(logical)
            try:
                _mount(_fd_path(fresh), _fd_path(target), None, _MS_BIND)
            finally:
                os.close(target)
            mounted = _source(logical, service_uid)
            try:
                if _identity(mounted) != expected:
                    raise HostUpgradeError("coordinator bind selected another inode")
                flags = _MS_REMOUNT | _MS_BIND | _MS_NOSUID | _MS_NODEV
                if readonly:
                    flags |= _MS_RDONLY
                _mount(None, _fd_path(mounted), None, flags)
            finally:
                os.close(mounted)
        view = CoordinatorHostView(layout, service_uid, os.getpid(), _namespace_id(), identities)
        _ACTIVE = view
        view.recheck()
        return view
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
