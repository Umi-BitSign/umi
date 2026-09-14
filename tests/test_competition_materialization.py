from __future__ import annotations

import os
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_host_anchor as anchor_module
from umi import competition_materialization as material
from umi.competition_host_activation import SuccessorWorkerExecutionLimits
from umi.competition_supervisor import (
    SuccessorSupervisorDirectivePage,
    successor_continuation_bytes,
    successor_source_config_sha256,
)
from umi.competition_supervisor_adapters import SuccessorArtifactFiles
from umi.competition_supervisor_runtime import SuccessorWorkerSelection
from umi.competition_worker_cli import SuccessorWorkerExecutionConfig
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import ValidatorSupervisorError

from .test_competition_chain import chain_config as chain_config
from .test_competition_host_activation import activation_case as activation_case
from .test_competition_host_anchor import anchor_case as anchor_case
from .test_competition_recovery import explicit as explicit
from .test_competition_recovery import limits as limits
from .test_competition_recovery import trusted_ports as trusted_ports
from .test_competition_supervisor import _signed, _signed_continuation
from .test_competition_supervisor import package_case as package_case
from .test_competition_supervisor import package_limits as package_limits
from .test_competition_supervisor import policy as policy
from .test_competition_supervisor import release_identity as release_identity
from .test_competition_supervisor import replay_limits as replay_limits
from .test_competition_supervisor import successor_case as successor_case
from .test_competition_supervisor import successor_chain as successor_chain
from .test_competition_supervisor import successor_release as successor_release
from .test_competition_supervisor import v3_predecessor as v3_predecessor
from .test_competition_worker import worker_capacity as worker_capacity

_REAL_EXCHANGE = material._exchange
_REAL_INSTALL_NOREPLACE = material._install_noreplace


def _restore_writable(path):
    if not path.is_dir() or path.is_symlink():
        return
    path.chmod(0o700)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            _restore_writable(child)


@pytest.fixture
def case(successor_case, package_case, worker_capacity, tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    config = successor_case.predecessor.config.model_copy(
        update={"state_root": str(state), "worker_state_root": str(tmp_path / "worker-state")}
    )
    consent = successor_case.consent.model_copy(
        update={"source_config_sha256": successor_source_config_sha256(config)}
    )
    selection = SuccessorWorkerSelection(successor_case.signed)
    page = SuccessorSupervisorDirectivePage(
        schema="umi-validator-supervisor-directive-page/4",
        after_version=3,
        after_sequence=successor_case.predecessor.state.accepted_sequence,
        after_directive_sha256=successor_case.predecessor.state.accepted_directive_sha256,
        directives=[selection.signed],
        more=False,
        head=selection.signed,
    )
    execution = SuccessorWorkerExecutionConfig(
        schema="umi-successor-worker-execution-config/1",
        replay_capacity=worker_capacity,
        weights=None,
    )
    worker_limits = SuccessorWorkerExecutionLimits(
        schema="umi-successor-worker-execution-limits/1",
        replay_capacity_ceiling=worker_capacity,
        maximum_weight_attempts=10,
        maximum_weight_evidence_bytes=1_000_000,
        maximum_submission_timeout_seconds=10,
    )
    limits = material.SuccessorCurrentMaterializationLimits(
        maximum_stages=5,
        maximum_cache_bytes=20_000_000,
        maximum_tree_entries=100,
        maximum_tree_depth=4,
    )
    files = SuccessorArtifactFiles(
        release_bundle_path=tmp_path / "not-read-by-materializer.bundle",
        package_path=package_case.path,
        worker_execution_bytes=canonical_json_bytes(execution),
        current_directive_page_bytes=canonical_json_bytes(page),
        authorization_bytes=None,
    )
    yield SimpleNamespace(
        config=config,
        consent=consent,
        selection=selection,
        files=files,
        page=page,
        limits=limits,
        worker_limits=worker_limits,
        state=state,
        package_case=package_case,
        execution=execution,
    )
    _restore_writable(state)


def _stage(case, **changes):
    values = dict(
        selection=case.selection,
        files=case.files,
        config=case.config,
        operator_consent=case.consent,
        worker_limits=case.worker_limits,
        limits=case.limits,
    )
    return material.stage_successor_current(**(values | changes))


def _test_exchange(cache_fd, name, source_fd):
    """Mac-only OS-port fixture, explicitly NOT evidence of atomic replacement."""
    os.rename(name, "test-exchange-in-progress", src_dir_fd=cache_fd, dst_dir_fd=cache_fd)
    os.rename("current", name, src_dir_fd=source_fd, dst_dir_fd=cache_fd)
    os.rename("test-exchange-in-progress", "current", src_dir_fd=cache_fd, dst_dir_fd=source_fd)


def _test_install_noreplace(cache_fd, name, source_fd):
    """Portable fixture only; Linux tests exercise the real atomic syscall."""
    try:
        os.stat("current", dir_fd=source_fd, follow_symlinks=False)
    except FileNotFoundError:
        os.rename(name, "current", src_dir_fd=cache_fd, dst_dir_fd=source_fd)
    else:
        raise FileExistsError("existing current")


@pytest.fixture
def installed(case, monkeypatch):
    first = _stage(case)
    source, cache = material.successor_materialization_paths(case.config)
    source.mkdir(mode=0o700)
    anchor_dir = source / "anchor"
    anchor_dir.mkdir(mode=0o700)
    marker = anchor_dir / "root-seal-fixture"
    marker.write_bytes(b"retained root seal fixture")
    marker.chmod(0o400)
    anchor_dir.chmod(0o555)
    shutil.copytree(first.path, source / "current")
    source.chmod(0o555)
    anchor_identity = material._identity(anchor_dir.stat())
    anchor_bytes = marker.read_bytes()
    anchor = SimpleNamespace(
        source_root=source,
        config=case.config,
        operator_consent=case.consent,
        worker_execution_limits=case.worker_limits,
    )

    def recheck():
        if (
            material._identity(anchor_dir.stat()) != anchor_identity
            or marker.read_bytes() != anchor_bytes
        ):
            raise material.SuccessorMaterializationError("root anchor changed")

    anchor.recheck = recheck
    anchor.recheck_for_parent_repair = recheck

    def verify_anchor(value, config, **kwargs):
        # Root-owner/authentication OS port is mocked; current signatures and
        # canonical package verification remain real in every operation.
        assert value is anchor and config == case.config
        recheck()
        return source

    monkeypatch.setattr(material, "_validate_anchor", verify_anchor)

    def verify_history(value, page, **kwargs):
        assert value is anchor
        assert page.after_version == case.page.after_version
        assert page.after_sequence == case.page.after_sequence
        assert page.after_directive_sha256 == case.page.after_directive_sha256

    monkeypatch.setattr(
        anchor_module, "verify_materialized_current_history", verify_history, raising=False
    )
    monkeypatch.setattr(
        anchor_module,
        "verify_materialized_current_history_for_repair",
        verify_history,
        raising=False,
    )
    if sys.platform != "linux":
        monkeypatch.setattr(material, "_exchange", _test_exchange)
    return SimpleNamespace(
        case=case,
        first=first,
        source=source,
        cache=cache,
        anchor=anchor,
        anchor_bytes=anchor_bytes,
        marker=marker,
    )


@pytest.fixture
def initial(installed, monkeypatch):
    value = installed
    # Preserve the existing fixture tree outside current; do not delete bytes.
    value.source.chmod(0o755)
    (value.source / "current").chmod(0o755)
    (value.source / "current").rename(value.cache / ("stage-" + "f" * 32))
    (value.cache / ("stage-" + "f" * 32)).chmod(0o555)
    value.source.chmod(0o555)
    page_bytes = canonical_json_bytes(value.case.page)
    value.anchor.initial_page = value.case.page
    value.anchor.receipt = SimpleNamespace(
        initial_successor_page_sha256=material._hash(page_bytes),
        initial_successor_page_size_bytes=len(page_bytes),
    )
    value.anchor.receipt_sha256 = "ab" * 32
    value.case.page = SuccessorSupervisorDirectivePage(
        schema="umi-validator-supervisor-directive-page/4",
        after_version=4,
        after_sequence=value.case.selection.signed.directive.sequence,
        after_directive_sha256=value.case.selection.directive_sha256,
        directives=[],
        more=False,
        head=value.case.selection.signed,
    )
    value.case.files = replace(
        value.case.files, current_directive_page_bytes=canonical_json_bytes(value.case.page)
    )
    if sys.platform != "linux":
        monkeypatch.setattr(material, "_install_noreplace", _test_install_noreplace)
    return value


def test_initial_current_preserves_signed_inputs_and_grants_no_authority(initial):
    value = initial
    staged = _stage(value.case)
    staged_inode = staged.path.stat().st_ino
    source_inode = value.source.stat().st_ino
    retained_before = {
        path: path.stat().st_ino for path in value.cache.glob("stage-*") if path != staged.path
    }
    result = material.install_initial_successor_current(staged, anchor=value.anchor)
    assert result.current_path.stat().st_ino == staged_inode
    assert result.source_root.stat().st_ino == source_inode
    assert result.directive_sha256 == value.case.selection.directive_sha256
    assert result.receipt_sha256 == value.anchor.receipt_sha256
    assert not hasattr(result, "activation") and not hasattr(result, "chain_submission_authorized")
    assert not staged.path.exists()
    assert retained_before
    assert all(path.stat().st_ino == inode for path, inode in retained_before.items())
    assert value.marker.read_bytes() == value.anchor_bytes
    assert stat.S_IMODE(value.source.stat().st_mode) == 0o555
    assert stat.S_IMODE(result.current_path.stat().st_mode) == 0o555
    page = result.current_path / material.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME
    assert page.read_bytes() == value.case.files.current_directive_page_bytes


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_initial_current_never_overwrites_existing_path(initial, kind):
    value = initial
    target = value.source / "current"
    value.source.chmod(0o755)
    if kind == "directory":
        target.mkdir(mode=0o555)
    elif kind == "file":
        target.write_bytes(b"retained current")
        target.chmod(0o400)
    else:
        target.symlink_to(value.source / "missing")
    value.source.chmod(0o555)
    identity = material._identity(target.lstat())
    staged = _stage(value.case)
    with pytest.raises(material.SuccessorMaterializationError, match="only the root anchor"):
        material.install_initial_successor_current(staged, anchor=value.anchor)
    assert material._identity(target.lstat()) == identity
    staged.recheck()


@pytest.mark.parametrize(
    "name",
    [
        "successor-v4-initialization.json",
        "successor-adapter",
        "successor-v4/runtime",
        "successor-v4/supervisor.sqlite3",
        "successor-v4/supervisor.sqlite3-journal",
        "successor-v4/supervisor.sqlite3-wal",
        "successor-v4/supervisor.sqlite3-shm",
    ],
)
def test_initial_current_refuses_any_retained_successor_history(initial, name):
    value = initial
    target = value.case.state / name
    target.write_bytes(b"retained history, even if malformed")
    target.chmod(0o600)
    staged = _stage(value.case)
    with pytest.raises(material.SuccessorMaterializationError, match="successor history"):
        material.install_initial_successor_current(staged, anchor=value.anchor)
    assert target.read_bytes() == b"retained history, even if malformed"
    assert not (value.source / "current").exists()
    staged.recheck()


def test_initial_current_rejects_different_initial_page(initial):
    value = initial
    # Same signed head but wrong wrapper: the v3 transition page cannot be
    # installed in the rolling view, which follows the sealed initial v4 head.
    files = replace(
        value.case.files,
        current_directive_page_bytes=canonical_json_bytes(value.anchor.initial_page),
    )
    staged = _stage(value.case, files=files)
    with pytest.raises(material.SuccessorMaterializationError, match="sealed initial page"):
        material.install_initial_successor_current(staged, anchor=value.anchor)
    staged.recheck()
    assert not (value.source / "current").exists()


@pytest.mark.parametrize(
    "field", ["initial_successor_page_sha256", "initial_successor_page_size_bytes"]
)
def test_initial_current_requires_receipt_exact_initial_page(initial, field):
    value = initial
    setattr(value.anchor.receipt, field, "00" * 32 if field.endswith("sha256") else 1)
    staged = _stage(value.case)
    with pytest.raises(material.SuccessorMaterializationError, match="sealed initial page"):
        material.install_initial_successor_current(staged, anchor=value.anchor)
    staged.recheck()
    assert not (value.source / "current").exists()


def test_initial_current_refuses_retained_worker_state(initial):
    from pathlib import Path

    value = initial
    worker = Path(value.case.config.worker_state_root)
    worker.mkdir(mode=0o700)
    (worker / "competition").mkdir(mode=0o700)
    staged = _stage(value.case)
    with pytest.raises(material.SuccessorMaterializationError, match="successor history"):
        material.install_initial_successor_current(staged, anchor=value.anchor)
    assert not (value.source / "current").exists()
    staged.recheck()


def test_initial_current_refuses_dangling_history_marker(initial):
    value = initial
    marker = value.case.state / "successor-v4-initialization.json"
    marker.symlink_to(value.case.state / "missing-history")
    staged = _stage(value.case)
    with pytest.raises(material.SuccessorMaterializationError, match="successor history"):
        material.install_initial_successor_current(staged, anchor=value.anchor)
    assert marker.is_symlink()
    assert not (value.source / "current").exists()


def test_initial_current_requires_authentic_staged_capability(initial):
    staged = replace(_stage(initial.case), _issuer=None)
    with pytest.raises(material.SuccessorMaterializationError, match="absent or altered"):
        material.install_initial_successor_current(staged, anchor=initial.anchor)
    assert not (initial.source / "current").exists()


def test_initial_current_has_no_nonatomic_platform_fallback(initial, monkeypatch):
    staged = _stage(initial.case)
    monkeypatch.setattr(material, "sys", SimpleNamespace(platform="unsupported"))
    monkeypatch.setattr(material, "_install_noreplace", _REAL_INSTALL_NOREPLACE)
    with pytest.raises(material.SuccessorMaterializationError, match="requires Linux"):
        material.install_initial_successor_current(staged, anchor=initial.anchor)
    assert (staged.path / "package" / "manifest.json").is_file()
    assert stat.S_IMODE(staged.path.stat().st_mode) == 0o555
    assert stat.S_IMODE(initial.source.stat().st_mode) == 0o555
    assert not (initial.source / "current").exists()


@pytest.mark.parametrize("when", ["before", "after"])
def test_initial_publication_failure_retains_bytes_and_reseals(initial, monkeypatch, when):
    value = initial
    staged = _stage(value.case)
    inode = staged.path.stat().st_ino
    publish = material._install_noreplace

    def fail(*args):
        if when == "after":
            publish(*args)
        raise OSError("injected initial publication failure")

    monkeypatch.setattr(material, "_install_noreplace", fail)
    with pytest.raises(OSError, match="injected"):
        material.install_initial_successor_current(staged, anchor=value.anchor)
    retained = value.source / "current" if when == "after" else staged.path
    assert retained.stat().st_ino == inode
    assert stat.S_IMODE(retained.stat().st_mode) == 0o555
    assert stat.S_IMODE(value.source.stat().st_mode) == 0o555
    assert (retained / "package" / "manifest.json").is_file()
    assert value.marker.read_bytes() == value.anchor_bytes


def test_initial_publication_rechecks_absent_history_after_slow_validation(initial, monkeypatch):
    value = initial
    staged = _stage(value.case)
    original = material._read_current

    def appear(*args, **kwargs):
        page = original(*args, **kwargs)
        (value.case.state / "successor-v4-initialization.json").write_bytes(b"new history")
        return page

    monkeypatch.setattr(material, "_read_current", appear)
    with pytest.raises(material.SuccessorMaterializationError, match="successor history"):
        material.install_initial_successor_current(staged, anchor=value.anchor)
    assert not (value.source / "current").exists()
    staged.recheck()


def test_initial_publication_reports_history_race_without_undoing_publication(initial, monkeypatch):
    value = initial
    staged = _stage(value.case)
    publish = material._install_noreplace
    marker = value.case.state / "successor-v4-initialization.json"

    def appear(*args):
        publish(*args)
        marker.write_bytes(b"history appeared after publication")

    monkeypatch.setattr(material, "_install_noreplace", appear)
    with pytest.raises(material.SuccessorMaterializationError, match="successor history"):
        material.install_initial_successor_current(staged, anchor=value.anchor)
    assert marker.read_bytes() == b"history appeared after publication"
    assert (value.source / "current" / "package" / "manifest.json").is_file()
    assert stat.S_IMODE((value.source / "current").stat().st_mode) == 0o555
    assert stat.S_IMODE(value.source.stat().st_mode) == 0o555


@pytest.mark.skipif(sys.platform != "linux", reason="actual renameat2 test requires Linux")
def test_real_linux_initial_publish_is_atomic_and_never_replaces_racing_path(initial, monkeypatch):
    value = initial
    staged = _stage(value.case)
    inode = staged.path.stat().st_ino

    def race(cache_fd, name, source_fd):
        os.mkdir("current", mode=0o555, dir_fd=source_fd)
        _REAL_INSTALL_NOREPLACE(cache_fd, name, source_fd)

    monkeypatch.setattr(material, "_install_noreplace", race)
    with pytest.raises(FileExistsError):
        material.install_initial_successor_current(staged, anchor=value.anchor)
    assert staged.path.stat().st_ino == inode
    assert list((value.source / "current").iterdir()) == []
    assert stat.S_IMODE(staged.path.stat().st_mode) == 0o555
    assert stat.S_IMODE(value.source.stat().st_mode) == 0o555


def test_staging_is_wallet_free_and_does_not_replace_current(case, monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("local materialization attempted an external operation")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    legacy = case.state / "journal.json"
    legacy.write_bytes(b"retained legacy bytes, not a new v4 cursor")
    legacy_before = material._identity(legacy.stat())
    staged = _stage(case)
    staged.recheck()
    source, cache = material.successor_materialization_paths(case.config)
    assert staged.path.parent == cache and not source.exists()
    assert (
        staged.path.name.startswith("stage-")
        and staged.path.name != case.selection.directive_sha256
    )
    assert stat.S_IMODE(staged.path.stat().st_mode) == 0o555
    assert stat.S_IMODE((staged.path / "package").stat().st_mode) == 0o500
    for path in staged.path.rglob("*"):
        if path.is_file():
            assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert not hasattr(staged, "chain_submission_authorized")
    assert not hasattr(staged, "activation")
    assert material._identity(legacy.stat()) == legacy_before
    assert legacy.read_bytes() == b"retained legacy bytes, not a new v4 cursor"


def test_stages_are_distinct_and_previous_bytes_retained(installed):
    value = installed
    second = _stage(value.case)
    previous_inode = (value.source / "current").stat().st_ino
    staged_inode = second.path.stat().st_ino
    source_inode = value.source.stat().st_ino
    result = material.select_staged_successor_current(second, anchor=value.anchor)
    assert result.current_path.stat().st_ino == staged_inode
    assert result.retained_previous_path.stat().st_ino == previous_inode
    assert value.source.stat().st_ino == source_inode
    assert value.marker.read_bytes() == value.anchor_bytes
    assert stat.S_IMODE(value.source.stat().st_mode) == 0o555
    assert value.first.path.exists()
    with pytest.raises(material.SuccessorMaterializationError, match="identities changed"):
        second.recheck()


@pytest.mark.skipif(sys.platform != "linux", reason="actual renameat2 test requires Linux")
def test_real_linux_exchange_keeps_nonempty_directories(installed):
    value = installed
    second = _stage(value.case)
    result = material.select_staged_successor_current(second, anchor=value.anchor)
    assert (result.current_path / "package" / "manifest.json").is_file()
    assert (result.retained_previous_path / "package" / "manifest.json").is_file()


def test_unavailable_exchange_has_no_nonatomic_production_fallback(installed, monkeypatch):
    second = _stage(installed.case)
    monkeypatch.setattr(material, "sys", SimpleNamespace(platform="unsupported"))
    # Undo only the Mac fixture's exchange replacement for this production check.
    monkeypatch.setattr(material, "_exchange", _REAL_EXCHANGE)
    before = (installed.source / "current").stat().st_ino
    with pytest.raises(material.SuccessorMaterializationError, match="requires Linux"):
        material.select_staged_successor_current(second, anchor=installed.anchor)
    assert (installed.source / "current").stat().st_ino == before
    assert stat.S_IMODE(installed.source.stat().st_mode) == 0o555


@pytest.mark.parametrize("when", ["before", "after"])
def test_exchange_failure_restores_parent_permissions_and_retains_both(
    installed, monkeypatch, when
):
    second = _stage(installed.case)
    exchange = material._exchange
    old = (installed.source / "current").stat().st_ino
    new = second.path.stat().st_ino

    def failure(*args):
        if when == "after":
            exchange(*args)
        raise OSError("injected exchange failure")

    monkeypatch.setattr(material, "_exchange", failure)
    with pytest.raises(OSError, match="injected"):
        material.select_staged_successor_current(second, anchor=installed.anchor)
    assert stat.S_IMODE(installed.source.stat().st_mode) == 0o555
    assert stat.S_IMODE(second.path.stat().st_mode) == 0o555
    assert stat.S_IMODE((installed.source / "current").stat().st_mode) == 0o555
    assert {second.path.stat().st_ino, (installed.source / "current").stat().st_ino} == {old, new}


def test_repair_only_narrows_valid_backing_parent(installed):
    installed.source.chmod(0o755)
    material.repair_successor_source_permissions(
        anchor=installed.anchor, limits=installed.case.limits
    )
    assert stat.S_IMODE(installed.source.stat().st_mode) == 0o555
    assert installed.marker.read_bytes() == installed.anchor_bytes


def test_repair_does_not_hide_corrupt_current(installed):
    installed.source.chmod(0o755)
    control = installed.source / "current" / material.WORKER_EXECUTION_FILENAME
    control.chmod(0o600)
    control.write_bytes(b"{}")
    control.chmod(0o400)
    with pytest.raises(ValueError):
        material.repair_successor_source_permissions(
            anchor=installed.anchor, limits=installed.case.limits
        )
    assert stat.S_IMODE(installed.source.stat().st_mode) == 0o755


def test_repair_reseals_interrupted_exchange_leaf_modes(installed):
    second = _stage(installed.case)
    old = installed.source / "current"
    identities = {old.stat().st_ino, second.path.stat().st_ino}
    installed.source.chmod(0o755)
    old.chmod(0o755)
    second.path.chmod(0o755)
    material.repair_successor_source_permissions(
        anchor=installed.anchor, limits=installed.case.limits
    )
    assert {old.stat().st_ino, second.path.stat().st_ino} == identities
    for path in (installed.source, old, second.path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o555
    assert installed.marker.read_bytes() == installed.anchor_bytes
    # Permission repair cannot refresh the old process-local staged capability.
    with pytest.raises(material.SuccessorMaterializationError, match="identities changed"):
        second.recheck()


def test_repair_rejects_corrupt_retained_leaf_before_any_permission_change(installed):
    second = _stage(installed.case)
    current = installed.source / "current"
    for path in (installed.source, current, second.path):
        path.chmod(0o755)
    control = second.path / material.WORKER_EXECUTION_FILENAME
    control.chmod(0o600)
    control.write_bytes(b"{}")
    control.chmod(0o400)
    with pytest.raises(ValueError):
        material.repair_successor_source_permissions(
            anchor=installed.anchor, limits=installed.case.limits
        )
    for path in (installed.source, current, second.path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o755


def test_repair_preserves_unfinished_private_stage(installed):
    unfinished = installed.cache / ("stage-" + "0" * 32)
    unfinished.mkdir(mode=0o700)
    (unfinished / "partial").write_bytes(b"retained partial write")
    (unfinished / "partial").chmod(0o600)
    installed.source.chmod(0o755)
    material.repair_successor_source_permissions(
        anchor=installed.anchor, limits=installed.case.limits
    )
    assert stat.S_IMODE(unfinished.stat().st_mode) == 0o700
    assert (unfinished / "partial").read_bytes() == b"retained partial write"


def test_selection_rejects_duck_typed_staged_capability(installed):
    genuine = _stage(installed.case)
    forged = SimpleNamespace(
        recheck=lambda: None,
        path=genuine.path,
        config=genuine.config,
        selection=genuine.selection,
    )
    before = (installed.source / "current").stat().st_ino
    with pytest.raises(material.SuccessorMaterializationError, match="absent or altered"):
        material.select_staged_successor_current(forged, anchor=installed.anchor)
    assert (installed.source / "current").stat().st_ino == before


def test_repair_rechecks_complete_input_before_resealing(installed, monkeypatch):
    installed.source.chmod(0o755)
    current = installed.source / "current"
    current.chmod(0o755)
    original = material._read_current

    def mutate_after_validation(*args, **kwargs):
        page = original(*args, **kwargs)
        control = current / material.WORKER_EXECUTION_FILENAME
        control.chmod(0o600)
        control.write_bytes(b"{}")
        control.chmod(0o400)
        return page

    monkeypatch.setattr(material, "_read_current", mutate_after_validation)
    with pytest.raises(material.SuccessorMaterializationError, match="changed before resealing"):
        material.repair_successor_source_permissions(
            anchor=installed.anchor, limits=installed.case.limits
        )
    assert stat.S_IMODE(current.stat().st_mode) == 0o755
    assert stat.S_IMODE(installed.source.stat().st_mode) == 0o755


@pytest.mark.parametrize(
    "fault", ["signature", "page-head", "partial-page", "execution", "authorization", "package"]
)
def test_invalid_inputs_fail_before_cache_write(case, fault):
    files = case.files
    selection = case.selection
    if fault == "signature":
        signed = selection.signed.model_copy(update={"signatures": []})
        selection = SimpleNamespace(signed=signed)
    elif fault == "page-head":
        body = case.selection.signed.directive.model_copy(update={"issued_at_block": 121})
        selection = SuccessorWorkerSelection(_signed(body))
    elif fault == "partial-page":
        # A full canonical page cannot claim `more` with its current head; malformed bytes fail.
        files = replace(
            files,
            current_directive_page_bytes=files.current_directive_page_bytes.replace(
                b'"more":false', b'"more":true'
            ),
        )
    elif fault == "execution":
        files = replace(files, worker_execution_bytes=b"{}")
    elif fault == "authorization":
        files = replace(files, authorization_bytes=b"{}")
    else:
        path = files.package_path / "evidence.json"
        path.chmod(0o600)
        path.write_bytes(b"{}")
        path.chmod(0o400)
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        _stage(case, files=files, selection=selection)
    assert not material.successor_materialization_paths(case.config)[1].exists()


def test_local_worker_config_cannot_exceed_root_ceiling(case):
    larger = case.execution.model_copy(
        update={
            "replay_capacity": case.execution.replay_capacity.model_copy(
                update={"maximum_receipts": 21}
            )
        }
    )
    files = replace(case.files, worker_execution_bytes=canonical_json_bytes(larger))
    with pytest.raises(ValueError, match="ceilings"):
        _stage(case, files=files)


def test_cache_quota_keeps_previous_and_partial_trees(case):
    limits = case.limits.model_copy(update={"maximum_stages": 1})
    first = _stage(case, limits=limits)
    before = first.path.stat().st_ino
    changed = case.execution.model_copy(
        update={
            "replay_capacity": case.execution.replay_capacity.model_copy(
                update={"maximum_receipts": 19}
            )
        }
    )
    files = replace(case.files, worker_execution_bytes=canonical_json_bytes(changed))
    with pytest.raises(material.SuccessorMaterializationError, match="cache is full"):
        _stage(case, limits=limits, files=files)
    assert first.path.stat().st_ino == before


def test_identical_inputs_reuse_verified_stage_at_capacity_and_after_restart(case):
    limits = case.limits.model_copy(update={"maximum_stages": 1})
    first = _stage(case, limits=limits)
    path, before = first.path, dict(first._records)
    del first  # No process-local staged capability survives this simulated restart.
    for _ in range(3):
        repeated = _stage(case, limits=limits)
        assert repeated.path == path
        assert repeated._records == before
        repeated.recheck()
    assert len(list(path.parent.glob("stage-*"))) == 1


def test_different_controls_never_reuse_previous_stage(case):
    first = _stage(case)
    changed = case.execution.model_copy(
        update={
            "replay_capacity": case.execution.replay_capacity.model_copy(
                update={"maximum_receipts": 19}
            )
        }
    )
    second = _stage(
        case, files=replace(case.files, worker_execution_bytes=canonical_json_bytes(changed))
    )
    assert first.path != second.path
    first.recheck()
    second.recheck()


def test_modified_sealed_stage_is_not_reused_or_deleted(case):
    first = _stage(case)
    control = first.path / material.WORKER_EXECUTION_FILENAME
    control.chmod(0o600)
    control.write_bytes(b"{}")
    control.chmod(0o400)
    second = _stage(case)
    assert first.path != second.path
    assert control.read_bytes() == b"{}"
    second.recheck()


def test_second_materializer_cannot_pass_cache_lock(case):
    first = _stage(case)
    cache = first.path.parent
    with (
        material._cache_lock(cache),
        pytest.raises(material.SuccessorMaterializationError, match="in progress"),
    ):
        _stage(case)


@pytest.mark.parametrize(
    "fault", ["file-bytes", "hardlink", "symlink", "fifo", "unsealed", "extra"]
)
def test_staged_capability_rejects_mutations(case, fault):
    staged = _stage(case)
    path = staged.path / material.WORKER_EXECUTION_FILENAME
    staged.path.chmod(0o700)
    if fault == "file-bytes":
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b" ")
        path.chmod(0o400)
    elif fault == "hardlink":
        os.link(path, staged.path / "extra")
    elif fault == "symlink":
        (staged.path / "extra").symlink_to(path)
    elif fault == "fifo":
        os.mkfifo(staged.path / "fifo")
    elif fault == "unsealed":
        path.chmod(0o600)
    else:
        (staged.path / "extra").write_bytes(b"unexpected")
        (staged.path / "extra").chmod(0o400)
    staged.path.chmod(0o555)
    with pytest.raises((OSError, material.SuccessorMaterializationError)):
        staged.recheck()


def test_partial_stage_survives_write_failure_and_counts_toward_quota(case, monkeypatch):
    original = material._write_at
    count = 0

    def fail_after_first(*args):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("simulated full disk")
        return original(*args)

    monkeypatch.setattr(material, "_write_at", fail_after_first)
    with pytest.raises(OSError, match="full disk"):
        _stage(case)
    cache = material.successor_materialization_paths(case.config)[1]
    retained = list(cache.glob("stage-*"))
    assert len(retained) == 1 and any(retained[0].iterdir())
    monkeypatch.setattr(material, "_write_at", original)
    with pytest.raises(material.SuccessorMaterializationError, match="cache is full"):
        _stage(case, limits=case.limits.model_copy(update={"maximum_stages": 1}))


def test_staged_capability_cannot_be_rebound(case):
    value = _stage(case)
    for forged in (
        replace(value, directive_sha256="00" * 32),
        replace(value, _issuer=None),
        replace(value, path=value.path.parent / "other"),
    ):
        with pytest.raises(material.SuccessorMaterializationError, match="absent or altered"):
            forged.recheck()


@pytest.mark.parametrize("roll_count", [0, 68])
def test_genuine_anchor_stage_exchange_and_repair_integration(
    request, monkeypatch, tmp_path, roll_count
):
    # The anchor fixture replaces only root-owner/syscall ports with this test
    # account. Its signed controls, receipt, retained recovery and capability
    # verification remain real; no production owner check is bypassed in code.
    from . import test_competition_host_activation as activation_tests

    original_config = activation_tests.v3_config

    def temporary_config(**kwargs):
        return original_config(**kwargs).model_copy(
            update={
                "state_root": str(tmp_path / "service-private-state"),
                "worker_state_root": str(tmp_path / "worker-state"),
            }
        )

    monkeypatch.setattr(activation_tests, "v3_config", temporary_config)
    item = request.getfixturevalue("anchor_case")
    anchor = anchor_module.materialize_successor_anchor(**item.kwargs)
    base = item.base
    files = SuccessorArtifactFiles(
        release_bundle_path=tmp_path / "not-read.bundle",
        package_path=base.package.path,
        worker_execution_bytes=canonical_json_bytes(base.execution),
        current_directive_page_bytes=canonical_json_bytes(base.current_page),
        authorization_bytes=None,
    )
    limits = material.SuccessorCurrentMaterializationLimits(
        maximum_stages=5,
        maximum_cache_bytes=20_000_000,
        maximum_tree_entries=100,
        maximum_tree_depth=4,
    )
    staged = material.stage_successor_current(
        selection=SuccessorWorkerSelection(base.signed),
        files=files,
        config=base.config,
        operator_consent=base.consent,
        worker_limits=base.limits,
        limits=limits,
    )
    if sys.platform != "linux":
        monkeypatch.setattr(material, "_install_noreplace", _test_install_noreplace)
    initial = material.install_initial_successor_current(staged, anchor=anchor)
    assert initial.receipt_sha256 == anchor.receipt_sha256
    assert initial.current_path == item.source_root / "current"
    continuation = _signed_continuation(base.signed, roll_count)
    selected = continuation[-1] if continuation else base.signed
    body = successor_continuation_bytes(base.signed, continuation)
    files = replace(files, current_directive_page_bytes=body)
    staged = material.stage_successor_current(
        selection=SuccessorWorkerSelection(selected, body),
        files=files,
        config=base.config,
        operator_consent=base.consent,
        worker_limits=base.limits,
        limits=limits,
    )
    anchor.recheck()
    if sys.platform != "linux":
        monkeypatch.setattr(material, "_exchange", _test_exchange)
    result = material.select_staged_successor_current(staged, anchor=anchor)
    assert result.current_path == item.source_root / "current"
    assert result.retained_previous_path.exists()
    assert (
        result.current_path / material.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME
    ).read_bytes() == body
    anchor.recheck()
    item.source_root.chmod(0o755)
    result.current_path.chmod(0o755)
    result.retained_previous_path.chmod(0o755)
    repaired_anchor = anchor_module.load_materialized_successor_anchor_for_repair(item.paths.config)
    material.repair_successor_source_permissions(anchor=repaired_anchor, limits=limits)
    anchor_module.load_materialized_successor_anchor(item.paths.config).recheck()
    for path in (item.source_root, result.current_path, result.retained_previous_path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o555
