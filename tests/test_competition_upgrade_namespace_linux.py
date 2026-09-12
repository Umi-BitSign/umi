"""Opt-in real mounts in forked processes on a wallet-free Linux test host."""

from __future__ import annotations

import errno
import hashlib
import os
import sys
import threading
import traceback
from pathlib import Path

import pytest

from tests.test_competition_host_artifacts import sign
from tests.test_validator_supervisor import _config
from umi import competition_host_artifacts as artifacts
from umi import competition_host_bundle as bundle
from umi import competition_upgrade_namespace as namespace

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_NAMESPACE_REHEARSAL") != "1",
    reason="requires root opt-in on a wallet-free Linux test host",
)


@pytest.fixture
def case(tmp_path, monkeypatch):
    assert os.geteuid() == 0
    assert str(tmp_path).startswith("/var/lib/umi-successor-hostbundle-pytest-")
    config = _config(target_platform=artifacts._current_platform())
    root = tmp_path / "signed-hosts"
    root.mkdir(mode=0o755)
    helpers = {
        "artifacts/umi-grandpa-finality-observer": 0o555,
        "artifacts/umi-substrate-proof-verifier": 0o555,
        "artifacts/raw_spec_finney.json": 0o444,
    }
    content = {
        name: ("inert fixture " + name).encode()
        for name in artifacts._REQUIRED_FILES | set(helpers)
    }
    records = [
        artifacts.HostArtifactFile(
            path=name,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            mode=helpers.get(name, 0o555 if name.startswith(".venv/bin/") else 0o444),
        )
        for name, data in sorted(content.items())
    ]
    manifest = artifacts.SuccessorHostArtifactManifest(
        schema=artifacts.HOST_ARTIFACT_SCHEMA,
        channel_id=config.channel_id,
        umi_git_revision="cd" * 20,
        target_platform=config.target_platform,
        host_entrypoint_profile="umi-competition-supervisor-host/1",
        total_size_bytes=sum(item.size_bytes for item in records),
        files=records,
    )
    signed = sign(manifest)
    archive = tmp_path / "host.bundle"
    archive.write_bytes(bundle.HOST_BUNDLE_MAGIC + b"".join(content[item.path] for item in records))
    archive.chmod(0o400)
    monkeypatch.setattr(artifacts, "_STAGE_PARENT", root)
    tree = bundle.stage_successor_host_bundle(
        archive, signed=signed, config=config, expected_manifest_sha256=signed.manifest_sha256
    )
    controls = tmp_path / "controls"
    controls.mkdir(mode=0o700)
    cache = controls / "finality-state"
    cache.mkdir(mode=0o700)
    try:
        yield dict(host_tree=tree, config=config, control_directory=controls)
    finally:
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts)):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)


def _fork_check(operation, *, expected=0):
    pid = os.fork()
    if pid == 0:
        try:
            operation()
        except BaseException:
            # Test fixtures contain no keys or live paths. Preserve assertion
            # details so a mount failure cannot be mistaken for a skipped test.
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == expected


def _mount_state():
    # Kernel mount tables only. No files in either real validator are read.
    return Path("/proc/self/mountinfo").read_bytes()


@pytest.mark.parametrize("crash", [False, True])
def test_private_helpers_cache_and_process_death_leave_parent_mounts_unchanged(case, crash):
    before_namespace, before_mounts = namespace._namespace_id(), _mount_state()

    def child():
        namespace.prepare_upgrade_observer_namespace(**case)
        assert namespace._namespace_id() != before_namespace
        sources = (
            ("artifacts/umi-grandpa-finality-observer", namespace.WORKER_FINALITY_BINARY),
            ("artifacts/umi-substrate-proof-verifier", namespace.WORKER_PROOF_BINARY),
            ("artifacts/raw_spec_finney.json", namespace.WORKER_CHAIN_SPEC),
        )
        for name, target in sources:
            original = case["host_tree"].path / name
            assert target.read_bytes() == original.read_bytes()
            assert (target.stat().st_dev, target.stat().st_ino) == (
                original.stat().st_dev,
                original.stat().st_ino,
            )
            with pytest.raises(OSError) as error:
                os.open(target, os.O_WRONLY)
            assert error.value.errno == errno.EROFS
        for base in namespace._BASES:
            with pytest.raises(OSError) as error:
                (base / "unexpected").mkdir()
            assert error.value.errno == errno.EROFS
        (namespace.WORKER_FINALITY_STATE_ROOT / "test-cache").write_bytes(b"recovery cache only")
        assert (
            case["control_directory"] / "finality-state/test-cache"
        ).read_bytes() == b"recovery cache only"
        if crash:
            os._exit(77)

    _fork_check(child, expected=77 if crash else 0)
    assert namespace._namespace_id() == before_namespace
    assert _mount_state() == before_mounts
    case["host_tree"].recheck()


def test_partial_private_mount_failure_never_propagates(case):
    before = _mount_state()

    def child():
        original = namespace._bind
        count = 0

        def fail_after_first(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 2:
                raise namespace.HostUpgradeError("injected second bind failure")
            return original(*args, **kwargs)

        namespace._bind = fail_after_first
        with pytest.raises(namespace.HostUpgradeError, match="second bind failure"):
            namespace.prepare_upgrade_observer_namespace(**case)
        assert os.getpid() == namespace._ENTERED_PID
        with pytest.raises(namespace.HostUpgradeError, match="repeated or inherited"):
            namespace._unshare_mounts()

    _fork_check(child)
    assert _mount_state() == before
    assert not list((case["control_directory"] / "finality-state").iterdir())


def test_threaded_upgrade_rejected_before_mounting(case):
    def child():
        before = _mount_state()
        stop = threading.Event()
        worker = threading.Thread(target=stop.wait, daemon=True)
        worker.start()
        try:
            with pytest.raises(namespace.HostUpgradeError, match="single-threaded"):
                namespace.prepare_upgrade_observer_namespace(**case)
            assert _mount_state() == before
        finally:
            stop.set()
            worker.join(timeout=5)

    _fork_check(child)


def test_replaced_source_during_unshare_rejected_before_overlay(case):
    before = _mount_state()

    def child():
        original = namespace._unshare_mounts
        original_mount = namespace._mount
        mounts = []

        def mount(*args):
            mounts.append(args)
            return original_mount(*args)

        def replace_cache():
            original()
            cache = case["control_directory"] / "finality-state"
            cache.rename(cache.with_name("retained-original-cache"))
            cache.mkdir(mode=0o700)

        namespace._unshare_mounts = replace_cache
        namespace._mount = mount
        with pytest.raises(namespace.HostUpgradeError, match="source changed across namespace"):
            namespace.prepare_upgrade_observer_namespace(**case)
        assert mounts == [(None, "/", None, namespace._MS_REC | namespace._MS_PRIVATE)]
        assert not list((case["control_directory"] / "finality-state").iterdir())

    _fork_check(child)
    assert _mount_state() == before


@pytest.mark.parametrize("change", ["symlink", "writable_helper", "unsafe_cache", "overlap"])
def test_invalid_sources_fail_before_namespace_creation(case, change):
    def child():
        before = _mount_state()
        cache = case["control_directory"] / "finality-state"
        if change == "symlink":
            cache.rename(cache.with_name("retained-cache"))
            cache.symlink_to(cache.with_name("retained-cache"), target_is_directory=True)
        elif change == "unsafe_cache":
            cache.chmod(0o777)
        elif change == "writable_helper":
            (case["host_tree"].path / "artifacts/raw_spec_finney.json").chmod(0o644)
        else:
            # This only changes a public config object. No wallet is opened.
            case["config"] = case["config"].model_copy(
                update={
                    "wallet": case["config"].wallet.model_copy(update={"path": "/opt/umi/wallets"})
                }
            )
        with pytest.raises((ValueError, OSError)):
            namespace.prepare_upgrade_observer_namespace(**case)
        assert namespace._ENTERED_PID is None
        assert _mount_state() == before

    _fork_check(child)
