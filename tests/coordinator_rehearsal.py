"""Two synthetic coordinator roots for opt-in Linux systemd rehearsals.

The parent test owns OS bind mounts and tears them down after its forked
upgrade process exits. Never call this fixture on a validator host. Existing
unmarked roots, accounts or units are refused, not adopted or overwritten.
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

from umi.competition_coordinator_namespace import CoordinatorLayout

from .factories import dev_wallet
from .test_competition_service_linux import _command, _owned_directory, _write

_RECORDS = Path("/var/lib/umi-coordinator-service-rehearsal")
_ACCOUNT_PREFIX = 2**31 + 8 * 65536


def fixture_validator_hotkey(instance):
    assert instance in {"0", "54"}
    return dev_wallet("//CoordinatorRehearsalValidator" + instance).hotkey.ss58_address


# Matches the deployed coordinator's namespace and sandbox. The fixture has no
# legacy executable or migration approval, so this text cannot start a writer.
LEGACY_FRAGMENT = """[Unit]
Description=UMI validator UID %i on coordinator
After=network-online.target
Wants=network-online.target
ConditionPathExists=/var/lib/umi-validator-hosts/uid%i/etc/umi/migration-approved
[Service]
Type=simple
User=umi-validator-uid%i
Group=umi-validator-uid%i
UMask=0077
RootDirectory=/var/lib/umi-validator-hosts/uid%i
MountAPIVFS=true
WorkingDirectory=/var/lib/umi-validator-supervisor
BindPaths=/run/umi-validator-uid%i:/run/umi-validator-supervisor
BindReadOnlyPaths=/etc/resolv.conf:/etc/resolv.conf
ExecStart=/bin/false
Restart=always
RestartSec=15s
TimeoutStartSec=180s
TimeoutStopSec=180s
KillMode=mixed
Slice=umi-validators.slice
CPUQuota=800%
TasksMax=512
LimitNOFILE=8192
LimitCORE=0
MemoryHigh=11811160064
MemoryMax=12884901888
OOMPolicy=stop
RuntimeDirectory=umi-validator-uid%i
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
PrivateTmp=true
KeyringMode=private
RemoveIPC=true
ProtectClock=true
ProtectHome=true
ProtectKernelModules=true
ProtectSystem=strict
ProtectProc=invisible
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
AmbientCapabilities=
Delegate=true
ReadOnlyPaths=+/etc/umi +/opt/umi-validator-supervisor \\
 +/var/lib/umi-validator-operator-inputs +/var/lib/umi-validator-runtime-wallets \\
 +/var/lib/umi-validator-runtime-smoke/readonly
ReadWritePaths=+/var/lib/umi-validator-supervisor +/var/lib/umi-validator-worker-state \\
 +/var/lib/umi-validator-runtime-smoke/readwrite +/run/umi-validator-supervisor
[Install]
WantedBy=multi-user.target
"""


def _public_file(path: Path, body: str):
    if path.exists():
        assert path.is_file() and not path.is_symlink()
        assert path.read_text() == body
    else:
        _write(path, body, 0o644)


def _rehearsal_account(layout: CoordinatorLayout):
    marker = _RECORDS / ("account-" + layout.instance + ".json")
    home = layout.physical(layout.account_home)
    try:
        user = pwd.getpwnam(layout.service_user)
    except KeyError:
        assert not marker.exists() and not layout.root_directory.exists()
        _command(
            "/usr/sbin/useradd",
            "--system",
            "--user-group",
            "--home-dir",
            home,
            "--shell",
            "/usr/sbin/nologin",
            layout.service_user,
        )
        user = pwd.getpwnam(layout.service_user)
        _write(marker, json.dumps({"uid": user.pw_uid, "gid": user.pw_gid, "home": str(home)}))
    assert user.pw_dir == str(home) and user.pw_shell == "/usr/sbin/nologin"
    assert json.loads(marker.read_bytes()) == {
        "uid": user.pw_uid,
        "gid": user.pw_gid,
        "home": str(home),
    }
    start = _ACCOUNT_PREFIX + (0 if layout.instance == "0" else 65536)
    for name, option in (("subuid", "--add-subuids"), ("subgid", "--add-subgids")):
        path = Path("/etc") / name
        rows = [line.split(":") for line in path.read_text().splitlines() if line]
        own = [row for row in rows if row[0] == layout.service_user]
        if own:
            assert own == [[layout.service_user, str(start), "65536"]]
        else:
            assert all(
                int(row[1]) + int(row[2]) <= start or int(row[1]) >= start + 65536 for row in rows
            )
            _command("/usr/sbin/usermod", option, f"{start}-{start + 65535}", layout.service_user)
    return user, start


def _prepare_root(layout, user, start):
    root = layout.root_directory
    if not root.exists():
        root.mkdir(parents=True, mode=0o755)
    for name in (
        "etc",
        "run",
        "proc",
        "sys",
        "dev",
        "tmp",
        "var",
        "var/lib",
        "var/tmp",
        "opt",
        "home",
    ):
        path = root / name
        path.mkdir(parents=True, mode=0o755, exist_ok=True)
        assert not path.is_symlink() and path.stat().st_uid == 0
    (root / "tmp").chmod(0o1777)
    (root / "var/tmp").chmod(0o1777)
    _public_file(
        root / "etc/passwd",
        (
            "root:x:0:0:root:/root:/bin/bash\n"
            f"umi-validator:x:{user.pw_uid}:{user.pw_gid}::{layout.account_home}:/usr/sbin/nologin\n"
        ),
    )
    _public_file(root / "etc/group", f"root:x:0:\numi-validator:x:{user.pw_gid}:\n")
    for name in ("subuid", "subgid"):
        _public_file(root / "etc" / name, f"umi-validator:{start}:65536\n")
    for name in ("nsswitch.conf", "hosts", "ld.so.cache", "login.defs"):
        if not (root / "etc" / name).exists():
            shutil.copyfile(Path("/etc") / name, root / "etc" / name)
    for name in ("pam.d", "security", "containers", "ssl"):
        source = Path("/etc") / name
        target = root / "etc" / name
        if source.exists() and not target.exists():
            shutil.copytree(source, target, symlinks=True)
    for logical in (
        "/etc/umi",
        "/opt/umi-validator-supervisor",
        "/var/lib/umi-validator-operator-inputs",
        "/var/lib/umi-validator-runtime-smoke/readonly",
    ):
        path = root / logical.lstrip("/")
        path.mkdir(parents=True, exist_ok=True, mode=0o755)
    for logical in (
        "/var/lib/umi-validator-supervisor",
        "/var/lib/umi-validator-supervisor/home",
        "/var/lib/umi-validator-supervisor/state",
        "/var/lib/umi-validator-supervisor/releases",
        "/var/lib/umi-validator-worker-state",
        "/var/lib/umi-validator-runtime-wallets",
        "/var/lib/umi-validator-runtime-smoke/readwrite",
        "/run/umi-validator-supervisor",
    ):
        _owned_directory(root / logical.lstrip("/"), user)
    # All data in this test wallet directory is deliberately non-key material.
    _public_file(root / "var/lib/umi-validator-runtime-wallets/inert-marker", "not a key\n")


def rooted_command(layout, user, *args, binds=(), **kwargs):
    """Execute a bounded fixture command with the same root and user bus."""
    import secrets

    environment = (
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG=C.UTF-8",
        f"HOME={layout.service_home}",
        "USER=umi-validator",
        "LOGNAME=umi-validator",
        f"XDG_RUNTIME_DIR=/run/user/{user.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{user.pw_uid}/bus",
    )
    return _command(
        "/usr/bin/systemd-run",
        "--quiet",
        "--pipe",
        "--wait",
        "--collect",
        "--unit=umi-rooted-fixture-command-" + secrets.token_hex(8),
        f"--property=User={user.pw_name}",
        f"--property=RootDirectory={layout.root_directory}",
        "--property=MountAPIVFS=yes",
        "--property=ProtectHome=tmpfs",
        "--property=Delegate=yes",
        f"--property=BindPaths=/run/user/{user.pw_uid}",
        *(("--property=BindReadOnlyPaths=" + " ".join(map(str, binds)),) if binds else ()),
        "--",
        "/usr/bin/env",
        "-i",
        *environment,
        *args,
        **kwargs,
    )


def rooted_podman(layout, user, *args, **kwargs):
    # The successor command adapter sanitizes its environment and takes HOME
    # from the inner passwd entry, not the supervisor's HOME environment.
    # Setup, inspection and cleanup must address that same image store.
    return rooted_command(
        layout,
        user,
        "/usr/bin/env",
        f"HOME={layout.account_home}",
        "/usr/bin/podman",
        "--cgroup-manager=systemd",
        *args,
        **kwargs,
    )


def release_fixture_runtime(layout, user):
    """End only the marked fixture account's idle rootless namespace."""
    marker = _RECORDS / ("account-" + layout.instance + ".json")
    assert json.loads(marker.read_bytes())["uid"] == user.pw_uid
    pause = Path(f"/run/user/{user.pw_uid}/libpod/tmp/pause.pid")
    if not pause.exists():
        return
    containers = json.loads(rooted_podman(layout, user, "ps", "--format=json").stdout)
    assert containers == [], "retaining a root with a live fixture container"
    rooted_podman(layout, user, "system", "migrate")
    assert not pause.exists()


@contextmanager
def coordinator_roots():
    assert sys.platform == "linux" and os.geteuid() == 0
    assert os.environ.get("UMI_RUN_COORDINATOR_SERVICE_REHEARSAL") == "1"
    # systemd launches probes in PID 1's mount namespace. The fixture's OS
    # binds must be visible there; only the upgrade child unshares afterward.
    assert os.stat("/proc/self/ns/mnt").st_ino == os.stat("/proc/1/ns/mnt").st_ino
    _RECORDS.mkdir(mode=0o755, exist_ok=True)
    assert not _RECORDS.is_symlink() and _RECORDS.stat().st_uid == 0
    assert stat.S_IMODE(_RECORDS.stat().st_mode) == 0o755
    units = []
    for uid in (0, 54):
        layout = CoordinatorLayout(f"umi-validator@{uid}.service")
        observed = _command(
            "/usr/bin/systemctl",
            "show",
            layout.unit_name,
            "--property=LoadState",
            "--value",
        ).stdout.strip()
        # A previous deliberately retained test unit needs its own recovery;
        # this initial fixture must not stop or overwrite it automatically.
        assert observed == b"not-found", "refusing an existing validator service"
        user, start = _rehearsal_account(layout)
        _prepare_root(layout, user, start)
        units.append((layout, user))
    mounted = []
    try:
        for layout, _ in units:
            for name in ("usr", "bin", "sbin", "lib", "lib64"):
                source = Path("/") / name
                if not source.exists():
                    continue
                target = layout.root_directory / name
                target.mkdir(mode=0o755, exist_ok=True)
                assert not target.is_symlink()
                assert _command("/usr/bin/mountpoint", "-q", target, check=False).returncode != 0
                assert not any(target.iterdir()), "refusing a populated test OS mount target"
                _command("/usr/bin/mount", "--bind", source, target)
                mounted.append(target)
                _command("/usr/bin/mount", "-o", "remount,bind,ro", target)
        yield units
    finally:
        # Only exact mounts created by this context are released. Test accounts
        # and their data remain for inspection; no recursive deletion occurs.
        for layout, user in units:
            release_fixture_runtime(layout, user)
        for target in reversed(mounted):
            _command("/usr/bin/umount", target)
