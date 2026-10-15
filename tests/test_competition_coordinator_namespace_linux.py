"""Real private mounts and locks, with both synthetic roots on a private tmpfs.

Run only with explicit UMI_RUN_COORDINATOR_NAMESPACE=1 in a root Linux rehearsal.
No service operation, network call or wallet access occurs. The outer unshare
ensures the fixture roots cannot replace the host's real validator directories.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from umi import competition_coordinator_namespace as coordinator
from umi import competition_upgrade_namespace as mounts
from umi.competition_host_upgrade import HostUpgradeError

_SERVICE_UID = int(os.environ.get("UMI_NAMESPACE_TEST_SERVICE_UID", "1001"))
_SERVICE_GID = int(os.environ.get("UMI_NAMESPACE_TEST_SERVICE_GID", "1001"))


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
        base = Path(os.environ.get("UMI_NAMESPACE_TEST_SCRATCH", "/var/lib")) / (
            "umi-coordinator-namespace-test-" + secrets.token_hex(8)
        )
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
    root.chmod(0o750)
    os.chown(root, 0, 0)
    for uid in (0, 54):
        layout = coordinator.CoordinatorLayout(f"umi-validator@{uid}.service")
        for logical, readonly in coordinator._ROOTS:
            path = layout.physical(logical)
            path.mkdir(parents=True, mode=0o755)
            os.chmod(path, 0o755 if readonly else 0o700)
            if not readonly:
                os.chown(path, _SERVICE_UID, _SERVICE_GID)
            # Public fixture metadata only, never a wallet file.
            (path / "namespace-fixture").write_text(str(uid))
        (layout.root_directory / "etc").mkdir(mode=0o755, exist_ok=True)
        (layout.root_directory / "etc/passwd").write_text(
            f"umi-validator:x:{_SERVICE_UID}:{_SERVICE_GID}::"
            "/var/lib/umi-validator-supervisor:/usr/sbin/nologin\n"
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
    os.chown(lock, _SERVICE_UID, _SERVICE_GID)
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
        view = coordinator.prepare_coordinator_host_view(unit_name=unit, service_uid=_SERVICE_UID)
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
        _writer_exchange_in_same_view(view, logical)
        with pytest.raises(HostUpgradeError, match="another validator"):
            coordinator.active_coordinator_view(other.unit_name)
        with pytest.raises(HostUpgradeError):
            coordinator.prepare_coordinator_host_view(unit_name=unit, service_uid=_SERVICE_UID)
        # Executables inherit the mounts but must obtain a new process-local
        # view. Repeated entry must preserve the same live writer lock; another
        # instance's service-owned target must not become an accepted alias.
        for mode in (
            "reenter",
            "reenter",
            "writer-exchange",
            "wrong-target",
            "service-drop",
            "service-wrong-group",
            "service-extra-group",
            "service-account-changed",
            "service-source-replaced",
            "service-source-symlink",
            "service-descriptor-replaced",
        ):
            account_path = layout.root_directory / "etc/passwd"
            account_bytes = account_path.read_bytes()
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    __spec__.name,
                    str(uid),
                    mode,
                    json.dumps([(str(path), ro) for path, ro in coordinator._ROOTS]),
                ],
                capture_output=True,
                timeout=30,
            )
            # These root-only corruptions live on the family's synthetic tmpfs.
            # Restore their named mappings before checking the parent's view.
            if mode == "service-account-changed":
                account_path.write_bytes(account_bytes)
            assert result.returncode == 0, mode + result.stdout.decode() + result.stderr.decode()
            view.recheck()
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


def _fresh_executable(uid, mode, roots):
    coordinator._ROOTS = tuple((Path(path), readonly) for path, readonly in json.loads(roots))
    assert coordinator.active_coordinator_view() is None
    unit = f"umi-validator@{uid}.service"
    layout = coordinator.CoordinatorLayout(unit)
    logical = coordinator._ROOTS[2][0]
    if mode == "wrong-target":
        # This deliberately altered fixture view is private to this child.
        mounts._unshare_mounts()
        other = coordinator.CoordinatorLayout(f"umi-validator@{54 if uid == 0 else 0}.service")
        source = coordinator._source(other.physical(logical), _SERVICE_UID)
        target = coordinator._source(logical, _SERVICE_UID)
        try:
            mounts._mount(mounts._fd_path(source), mounts._fd_path(target), None, mounts._MS_BIND)
        finally:
            os.close(source)
            os.close(target)
        # The fixture alteration itself needed one namespace preparation.
        # Exec again so the tested coordinator entry owns no inherited Python
        # capability; only the deliberately mismatched kernel mount survives.
        os.execv(
            sys.executable,
            [sys.executable, "-m", __spec__.name, str(uid), "wrong-target-check", roots],
        )
    if mode == "wrong-target-check":
        with pytest.raises(HostUpgradeError, match="inherited target differs"):
            coordinator.prepare_coordinator_host_view(unit_name=unit, service_uid=_SERVICE_UID)
        return
    assert mode in {"reenter", "writer-exchange"} or mode.startswith("service-")
    view = coordinator.prepare_coordinator_host_view(unit_name=unit, service_uid=_SERVICE_UID)
    assert not os.get_inheritable(view._root_descriptor)
    if mode == "writer-exchange":
        _writer_exchange_in_same_view(view, logical)
        return
    if mode.startswith("service-"):
        _dropped_service_check(view, logical, mode)
        return
    assert (logical / "namespace-fixture").read_text() == str(uid)
    with (logical / "supervisor-process.lock").open() as stream, pytest.raises(BlockingIOError):
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    for root, readonly in coordinator._ROOTS:
        assert root.stat().st_ino == layout.physical(root).stat().st_ino
        if readonly:
            with pytest.raises(OSError) as error:
                (root / "forbidden-child-write").write_bytes(b"denied")
            assert error.value.errno == errno.EROFS
    view.recheck()


def _writer_exchange_in_same_view(view, logical):
    from umi import competition_reward_writer_selection as selection

    # All bytes live on the fixture tmpfs, behind genuine private bind aliases.
    # The retained journal paths must stay logical across exchange and rollback.
    parent = logical / "exchange-fixture"
    parent.mkdir(mode=0o700)
    original = parent / "history"
    staged_parent = view.layout.root_directory.parent / "writer-preparation"
    staged_parent.mkdir(mode=0o700)
    staged = staged_parent / "history"
    original.mkdir(mode=0o700)
    staged.mkdir(mode=0o700)
    (original / "source").write_bytes(b"retained")
    (staged / "candidate").write_bytes(b"verified")
    physical = view.layout.physical(original)
    before = original.stat().st_ino, staged.stat().st_ino
    with pytest.raises(OSError) as error:
        os.rename(original, staged)
    assert error.value.errno == errno.EXDEV
    assert (original.stat().st_ino, staged.stat().st_ino) == before
    for _ in range(2):
        selection._exchange(original, staged)
        assert (original.stat().st_ino, staged.stat().st_ino) == before[::-1]
        assert physical.stat().st_ino == original.stat().st_ino
        assert (original / "candidate").read_bytes() == b"verified"
        assert (staged / "source").read_bytes() == b"retained"
        selection._exchange(original, staged)
        assert (original.stat().st_ino, staged.stat().st_ino) == before
    # An unselected nested mount can preserve the top view while redirecting a
    # descendant. Its differing parent must refuse without moving either tree.
    shadow = view.layout.root_directory.parent / "writer-shadow"
    shadow.mkdir(mode=0o700)
    (shadow / "history").mkdir(mode=0o700)
    source_fd = os.open(shadow, os.O_RDONLY | os.O_DIRECTORY)
    target_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        mounts._mount(mounts._fd_path(source_fd), mounts._fd_path(target_fd), None, mounts._MS_BIND)
    finally:
        os.close(source_fd)
        os.close(target_fd)
    view.recheck()
    with pytest.raises(ValueError, match="physical alias differs"):
        selection._exchange(original, staged)
    assert (physical.stat().st_ino, staged.stat().st_ino) == before
    # This mount exists only in the current private namespace; leave fixture
    # names distinct for the fresh-executable repetition below.
    subprocess.run(["/usr/bin/umount", str(parent)], check=True)
    (physical / "source").unlink()
    physical.rmdir()
    parent.rmdir()
    (staged / "candidate").unlink()
    staged.rmdir()
    staged_parent.rmdir()
    (shadow / "history").rmdir()
    shadow.rmdir()


def _dropped_service_check(view, logical, mode):
    layout = view.layout
    expected = None
    # Root-only fixture corruption before dropping every real/saved identity.
    # It happens in this executable's private view and cannot reach host state.
    if mode == "service-account-changed":
        path = layout.root_directory / "etc/passwd"
        path.write_text(path.read_text().replace(f":{_SERVICE_GID}::", f":{_SERVICE_GID + 1}::"))
        expected = "inner account group changed"
    elif mode in {"service-source-replaced", "service-source-symlink"}:
        replacement = layout.root_directory / ("fixture-" + mode)
        replacement.mkdir(mode=0o755)
        if mode == "service-source-symlink":
            # Overlay the first source's parent only in this private namespace.
            # Its first physical descendant is now a symlink, which must never
            # be followed by the selected-instance descriptor reader.
            source = layout.physical(coordinator._ROOTS[0][0])
            (replacement / source.name).symlink_to("/unselected-fixture-target")
            target_path = source.parent
        else:
            replacement.chmod(0o700)
            os.chown(replacement, _SERVICE_UID, _SERVICE_GID)
            target_path = layout.physical(logical)
        source_fd = os.open(replacement, os.O_RDONLY | os.O_DIRECTORY)
        target_fd = os.open(target_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            mounts._mount(
                mounts._fd_path(source_fd), mounts._fd_path(target_fd), None, mounts._MS_BIND
            )
        finally:
            os.close(source_fd)
            os.close(target_fd)
        expected = "preserved inode" if mode == "service-source-replaced" else OSError
    elif mode == "service-descriptor-replaced":
        other = coordinator.CoordinatorLayout(
            f"umi-validator@{54 if layout.instance == '0' else 0}.service"
        )
        descriptor = os.open(other.root_directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.dup2(descriptor, view._root_descriptor)
        finally:
            os.close(descriptor)
        expected = "selected instance descriptor changed"
    elif mode in {"service-wrong-group", "service-extra-group"}:
        expected = "dropped service identity"
    os.setgroups([_SERVICE_GID] if mode == "service-extra-group" else [])
    os.setgid(_SERVICE_GID + 1 if mode == "service-wrong-group" else _SERVICE_GID)
    os.setuid(_SERVICE_UID)
    assert os.getresuid() == (_SERVICE_UID,) * 3
    with pytest.raises(PermissionError):
        (layout.root_directory / "etc/passwd").stat()
    if expected is not None:
        if isinstance(expected, str):
            with pytest.raises(HostUpgradeError, match=expected):
                view.recheck()
        else:
            with pytest.raises(expected) as error:
                view.recheck()
            assert error.value.errno == errno.ELOOP
        return
    assert os.getresgid() == (_SERVICE_GID,) * 3 and not os.getgroups()
    assert coordinator.active_coordinator_view(layout.unit_name) is view
    assert (logical / "namespace-fixture").read_text() == layout.instance
    with (logical / "supervisor-process.lock").open() as stream, pytest.raises(BlockingIOError):
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    view.recheck()


def _observer_in_same_view(view):
    from .test_competition_upgrade_namespace_linux import case

    root = Path(os.environ.get("UMI_NAMESPACE_TEST_SCRATCH", "/var/lib")) / (
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
    if len(sys.argv) == 4:
        _fresh_executable(int(sys.argv[1]), sys.argv[2], sys.argv[3])
    else:
        _child(int(sys.argv[1]))
