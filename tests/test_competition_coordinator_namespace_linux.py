"""Real private mounts and locks, with both synthetic roots on a private tmpfs.

Run only with explicit UMI_RUN_COORDINATOR_NAMESPACE=1 in a root Linux rehearsal.
No service operation, network call or wallet access occurs. The outer unshare
ensures the fixture roots cannot replace the host's real validator directories.
"""

from __future__ import annotations

import errno
import fcntl
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from umi import competition_coordinator_namespace as coordinator
from umi import competition_upgrade_namespace as mounts
from umi.competition_host_upgrade import HostUpgradeError

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_COORDINATOR_NAMESPACE") != "1",
    reason="requires explicit root opt-in to the wallet-free coordinator namespace rehearsal",
)


def _fixture_roots():
    assert os.geteuid() == 0
    assert mounts._namespace_id() != mounts._namespace_id("/proc/1/ns/mnt")
    if os.environ.get("UMI_NAMESPACE_TEST_ROOTED_TARGETS") == "1":
        # Hosted runners may have a world-writable /opt. Keep the production
        # ownership checks and put fixture alias targets below a root-owned path.
        base = Path("/var/lib") / ("umi-coordinator-namespace-test-" + secrets.token_hex(8))
        base.mkdir(mode=0o755)
        coordinator._ROOTS = tuple(
            (base / str(index), readonly) for index, (_, readonly) in enumerate(coordinator._ROOTS)
        )
    root = Path("/var/lib/umi-validator-hosts")
    descriptor = mounts._ensure_base(root)
    try:
        mounts._mount(
            "tmpfs",
            mounts._fd_path(descriptor),
            "tmpfs",
            mounts._MS_NODEV | mounts._MS_NOSUID,
            "size=4194304,nr_inodes=1024,mode=0755",
        )
    finally:
        os.close(descriptor)
    for uid in (0, 54):
        layout = coordinator.CoordinatorLayout(f"umi-validator@{uid}.service")
        for logical, readonly in coordinator._ROOTS:
            path = layout.physical(logical)
            path.mkdir(parents=True, mode=0o755)
            os.chmod(path, 0o755 if readonly else 0o700)
            if not readonly:
                os.chown(path, 1001, 1001)
            # Public fixture metadata only, never a wallet file.
            (path / "namespace-fixture").write_text(str(uid))
        (layout.root_directory / "etc").mkdir(mode=0o755, exist_ok=True)
        (layout.root_directory / "etc/passwd").write_text(
            "umi-validator:x:1001:1001::/var/lib/umi-validator-supervisor:/usr/sbin/nologin\n"
        )
    return root


def _child(uid: int):
    _fixture_roots()
    unit = f"umi-validator@{uid}.service"
    layout = coordinator.CoordinatorLayout(unit)
    other = coordinator.CoordinatorLayout(f"umi-validator@{54 if uid == 0 else 0}.service")
    logical = coordinator._ROOTS[2][0]
    physical = layout.physical(logical)
    lock = physical / "supervisor-process.lock"
    lock.touch(mode=0o600)
    os.chown(lock, 1001, 1001)
    writer = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import fcntl,sys; f=open(sys.argv[1]); "
                "fcntl.flock(f,fcntl.LOCK_EX); print('held',flush=True); sys.stdin.read()"
            ),
            str(lock),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert writer.stdout.readline() == b"held\n"
        other_before = other.physical(logical).stat()
        view = coordinator.prepare_coordinator_host_view(unit_name=unit, service_uid=1001)
        assert (logical / "namespace-fixture").read_text() == str(uid)
        assert (logical / "supervisor-process.lock").stat().st_ino == lock.stat().st_ino
        with (logical / "supervisor-process.lock").open() as file, pytest.raises(BlockingIOError):
            fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for root, readonly in coordinator._ROOTS:
            assert root.stat().st_ino == layout.physical(root).stat().st_ino
            if readonly:
                with pytest.raises(OSError) as error:
                    (root / "forbidden-write").write_bytes(b"denied")
                assert error.value.errno == errno.EROFS
        (logical / "new-state").write_bytes(b"retained")
        assert (physical / "new-state").read_bytes() == b"retained"
        assert not (other.physical(logical) / "new-state").exists()
        assert other.physical(logical).stat().st_ino == other_before.st_ino
        view.recheck()
        with pytest.raises(HostUpgradeError, match="another validator"):
            coordinator.active_coordinator_view(other.unit_name)
        with pytest.raises(HostUpgradeError):
            coordinator.prepare_coordinator_host_view(unit_name=unit, service_uid=1001)
        writer.communicate(timeout=10)
        assert writer.returncode == 0
        with (logical / "supervisor-process.lock").open() as file:
            fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Mount capabilities are process-local, including after fork.
        pid = os.fork()
        if pid == 0:
            try:
                coordinator.active_coordinator_view(unit)
            except HostUpgradeError:
                os._exit(0)
            os._exit(1)
        assert os.waitpid(pid, 0)[1] == 0
        view.recheck()
        _observer_in_same_view(view)
    finally:
        if writer.poll() is None:
            writer.kill()
            writer.wait(timeout=10)


def _observer_in_same_view(view):
    from .test_competition_upgrade_namespace_linux import case

    root = Path("/var/lib") / (
        "umi-successor-hostbundle-pytest-coordinator-combined-" + secrets.token_hex(8)
    )
    root.mkdir(mode=0o755)
    with pytest.MonkeyPatch.context() as patch:
        fixture = case.__wrapped__(root, patch)
        arguments = next(fixture)
        try:
            before = mounts._namespace_id()
            mounts.prepare_upgrade_observer_namespace(**arguments)
            assert mounts._namespace_id() == before == view.namespace
            view.recheck()
            assert mounts.WORKER_FINALITY_BINARY.read_bytes().startswith(b"inert fixture")
            (mounts.WORKER_FINALITY_STATE_ROOT / "probe").write_bytes(b"observer-private")
            assert (
                arguments["control_directory"] / "finality-state/probe"
            ).read_bytes() == b"observer-private"
            with pytest.raises(HostUpgradeError, match="repeated or inherited"):
                mounts.prepare_upgrade_observer_namespace(**arguments)
            view.recheck()
        finally:
            fixture.close()


@pytest.mark.parametrize("uid", [0, 54])
def test_private_instance_views_share_original_lock_without_cross_instance_writes(uid):
    assert os.geteuid() == 0
    roots = [root for root, _ in coordinator._ROOTS]
    before = {path: path.stat().st_ino if path.exists() else None for path in roots}
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))
    result = subprocess.run(
        [
            "/usr/bin/unshare",
            "--mount",
            "--propagation",
            "private",
            "--",
            sys.executable,
            "-m",
            "tests.test_competition_coordinator_namespace_linux",
            str(uid),
        ],
        cwd=Path(__file__).parents[1],
        env=env,
        capture_output=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()
    for path, inode in before.items():
        if inode is not None:
            assert path.stat().st_ino == inode
        assert not (path / "namespace-fixture").exists()
        assert not (path / "new-state").exists()


if __name__ == "__main__":
    assert os.environ.get("UMI_RUN_COORDINATOR_NAMESPACE") == "1"
    _child(int(sys.argv[1]))
