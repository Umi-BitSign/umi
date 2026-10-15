"""Reuse only a fully checked immutable anchor with current complete identities."""

import os
from dataclasses import replace

import pytest

from umi import competition_host_activation as activation
from umi import competition_host_anchor as anchor

from .test_competition_host_anchor import _materialize
from .test_competition_host_anchor import activation_case as activation_case
from .test_competition_host_anchor import anchor_case as anchor_case
from .test_competition_host_anchor import chain_config as chain_config
from .test_competition_host_anchor import explicit as explicit
from .test_competition_host_anchor import limits as limits
from .test_competition_host_anchor import package_case as package_case
from .test_competition_host_anchor import package_limits as package_limits
from .test_competition_host_anchor import policy as policy
from .test_competition_host_anchor import release_identity as release_identity
from .test_competition_host_anchor import replay_limits as replay_limits
from .test_competition_host_anchor import successor_release as successor_release
from .test_competition_host_anchor import trusted_ports as trusted_ports
from .test_competition_host_anchor import worker_capacity as worker_capacity


def recovery_object(capability):
    objects = (
        capability.anchor_path
        / activation.RECOVERY_DIRECTORY_NAME
        / capability.receipt.checkpoint_sha256
        / "objects"
    )
    return next(path for path in objects.iterdir() if path.stat().st_size > 0)


def test_unchanged_rechecks_reuse_full_snapshot_but_retain_parent_and_current_checks(
    anchor_case, monkeypatch
):
    c = anchor_case
    capability = _materialize(c)
    assert capability._snapshot_reuse.pid == os.getpid()
    monkeypatch.setattr(
        anchor,
        "_snapshot_anchor",
        lambda *args, **kwargs: pytest.fail("unchanged payload verified again"),
    )
    for _ in range(4):
        capability.recheck()
        capability.recheck_for_parent_repair()
    c.source_root.chmod(0o755)
    with pytest.raises(anchor.SuccessorAnchorError, match="owner or mode"):
        capability.recheck()
    capability.recheck_for_parent_repair()
    (c.source_root / activation.CURRENT_DIRECTORY_NAME).mkdir(mode=0o555)
    capability.recheck_for_parent_repair()
    c.source_root.chmod(0o555)
    capability.recheck()


def test_changed_metadata_gets_full_check_once_before_new_reuse(anchor_case, monkeypatch):
    capability = _materialize(anchor_case)
    original = anchor._snapshot_anchor
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(anchor, "_snapshot_anchor", counted)
    target = capability.anchor_path / activation.WORKER_LIMITS_FILENAME
    before = target.stat()
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
    capability.recheck()
    capability.recheck()
    assert calls == [True]


@pytest.mark.parametrize("change", ["pid", "missing"])
def test_new_process_or_absent_process_cache_rechecks_initial_payload(
    anchor_case, monkeypatch, change
):
    capability = _materialize(anchor_case)
    original = anchor._snapshot_anchor
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(anchor, "_snapshot_anchor", counted)
    if change == "missing":
        object.__setattr__(capability, "_snapshot_reuse", None)
    else:
        value = replace(capability._snapshot_reuse, pid=os.getpid() + 1)
        object.__setattr__(value, "_binding", value.seal())
        object.__setattr__(capability, "_snapshot_reuse", value)
    capability.recheck_for_parent_repair()
    capability.recheck_for_parent_repair()
    assert calls == [True]


@pytest.mark.parametrize("change", ["capability", "reuse", "issuer"])
def test_cached_success_cannot_bypass_capability_and_cache_binding(anchor_case, change):
    capability = _materialize(anchor_case)
    if change == "capability":
        capability = replace(capability, receipt_sha256="ab" * 32)
    elif change == "reuse":
        object.__setattr__(
            capability, "_snapshot_reuse", replace(capability._snapshot_reuse, metadata=())
        )
    else:
        object.__setattr__(
            capability, "_snapshot_reuse", replace(capability._snapshot_reuse, _issuer=None)
        )
    with pytest.raises(anchor.SuccessorAnchorError, match="absent or altered"):
        capability.recheck()


@pytest.mark.parametrize("which", ["control", "object"])
def test_same_length_changed_payload_with_restored_mtime_is_rejected(anchor_case, which):
    capability = _materialize(anchor_case)
    target = (
        capability.anchor_path / activation.WORKER_LIMITS_FILENAME
        if which == "control"
        else recovery_object(capability)
    )
    before = target.stat()
    raw = target.read_bytes()
    assert raw
    target.chmod(0o644)
    target.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    target.chmod(0o444)
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ValueError):
        capability.recheck()


@pytest.mark.parametrize("change", ["symlink", "hardlink", "extra", "mode", "directory_symlink"])
def test_complete_inventory_links_and_modes_are_checked_on_reuse(anchor_case, change):
    capability = _materialize(anchor_case)
    root = capability.anchor_path
    root.chmod(0o755)
    target = root / activation.WORKER_LIMITS_FILENAME
    if change == "symlink":
        target.unlink()
        target.symlink_to(anchor_case.paths.limits)
    elif change == "hardlink":
        os.link(target, anchor_case.controls / "extra-hardlink")
    elif change == "extra":
        (root / "unexpected").write_bytes(b"extra")
        (root / "unexpected").chmod(0o444)
    elif change == "mode":
        target.chmod(0o400)
    else:
        recovery = root / activation.RECOVERY_DIRECTORY_NAME
        relocated = anchor_case.controls / "recovery-moved"
        recovery.chmod(0o755)
        recovery.rename(relocated)
        relocated.chmod(0o555)
        recovery.symlink_to(relocated, target_is_directory=True)
    root.chmod(0o555)
    with pytest.raises((ValueError, OSError)):
        capability.recheck_for_parent_repair()


def test_full_snapshot_does_not_seed_reuse_after_mid_check_payload_mutation(
    anchor_case, monkeypatch
):
    capability = _materialize(anchor_case)
    object.__setattr__(capability, "_snapshot_reuse", None)
    target = recovery_object(capability)
    original = activation._verify_retained_recovery_body

    def change_after_verify(*args, **kwargs):
        original(*args, **kwargs)
        raw = target.read_bytes()
        target.chmod(0o644)
        target.write_bytes(raw + b"changed")
        target.chmod(0o444)

    monkeypatch.setattr(activation, "_verify_retained_recovery_body", change_after_verify)
    with pytest.raises(anchor.SuccessorAnchorError, match="changed during full snapshot"):
        capability.recheck()
    assert capability._snapshot_reuse is None


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires actual process fork")
def test_actual_fork_requires_one_child_snapshot_before_reuse(anchor_case, monkeypatch):
    import json

    capability = _materialize(anchor_case)
    original = anchor._snapshot_anchor
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(anchor, "_snapshot_anchor", counted)
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        result = {}
        try:
            capability.recheck_for_parent_repair()
            capability.recheck_for_parent_repair()
            result = {"checks": len(calls), "reuse_pid": capability._snapshot_reuse.pid}
        except BaseException as error:
            result = {"error": type(error).__name__}
        finally:
            os.write(write, json.dumps(result).encode())
            os.close(write)
            os._exit(0)
    os.close(write)
    try:
        payload = os.read(read, 4096)
    finally:
        os.close(read)
        _, status = os.waitpid(pid, 0)
    assert status == 0
    assert json.loads(payload) == {"checks": 1, "reuse_pid": pid}
    capability.recheck()
    assert calls == []
    assert capability._snapshot_reuse.pid == os.getpid()


def test_named_file_replacement_during_metadata_walk_is_refused(anchor_case, monkeypatch):
    capability = _materialize(anchor_case)
    root = capability.anchor_path
    name = activation.WORKER_LIMITS_FILENAME
    target = root / name
    replacement = anchor_case.controls / "replacement-worker-limits"
    replacement.write_bytes(target.read_bytes())
    replacement.chmod(0o444)
    original = os.open
    swapped = False

    def swap_after_open(path, flags, *args, **kwargs):
        nonlocal swapped
        descriptor = original(path, flags, *args, **kwargs)
        if path == name and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            root.chmod(0o755)
            os.replace(replacement, target)
            root.chmod(0o555)
        return descriptor

    monkeypatch.setattr(os, "open", swap_after_open)
    with pytest.raises(anchor.SuccessorAnchorError, match="changed"):
        capability.recheck_for_parent_repair()
    assert swapped
