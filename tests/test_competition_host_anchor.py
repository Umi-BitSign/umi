from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_activation as activation
from umi import competition_host_anchor as anchor
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import ValidatorSupervisorError

from .test_competition_chain import chain_config as chain_config
from .test_competition_host_activation import _host_tree, _restore_writable, _write_control
from .test_competition_host_activation import activation_case as activation_case
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_recovery import explicit as explicit
from .test_competition_recovery import limits as limits
from .test_competition_recovery import trusted_ports as trusted_ports
from .test_competition_supervisor import successor_release as successor_release
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as policy


def _portable_mkdir(parent: int, name: str) -> None:
    os.fchmod(parent, 0o755)
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    finally:
        os.fchmod(parent, 0o555)


def _portable_rename_noreplace(parent: int, source: str, destination: str) -> None:
    os.fchmod(parent, 0o755)
    try:
        try:
            os.stat(destination, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise anchor.SuccessorAnchorError("successor anchor already exists")
        os.rename(source, destination, src_dir_fd=parent, dst_dir_fd=parent)
    finally:
        os.fchmod(parent, 0o555)


@pytest.fixture
def anchor_case(tmp_path, monkeypatch, activation_case):
    base = activation_case
    host = _host_tree(tmp_path / "anchor-host", monkeypatch, base.config)
    controls = tmp_path / "root-private-anchor-controls"
    controls.mkdir(mode=0o700)
    paths = SimpleNamespace(
        config=controls / activation.SOURCE_CONFIG_FILENAME,
        consent=controls / activation.OPERATOR_CONSENT_FILENAME,
        legacy=controls / activation.LEGACY_SIGNED_DIRECTIVE_FILENAME,
        initial=controls / activation.INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
        host=controls / activation.SIGNED_HOST_ARTIFACT_FILENAME,
        limits=controls / activation.WORKER_LIMITS_FILENAME,
        observer=controls / activation.HOST_OBSERVER_FILENAME,
    )
    _write_control(paths.config, base.config)
    _write_control(paths.consent, base.consent)
    _write_control(paths.legacy, base.predecessor.signed)
    _write_control(paths.initial, base.initial_page)
    _write_control(paths.host, host.signed)
    _write_control(paths.limits, base.limits)
    _write_control(paths.observer, base.observer_config)

    state_root = tmp_path / "service-private-state"
    successor_root = state_root / "successor-v4"
    source_root = successor_root / anchor.ACTIVATION_SOURCE_DIRECTORY_NAME
    source_root.mkdir(mode=0o700, parents=True)
    state_root.chmod(0o700)
    successor_root.chmod(0o700)
    source_root.chmod(0o555)

    monkeypatch.setattr(anchor, "_require_root_linux", lambda: None)
    monkeypatch.setattr(anchor, "_root_owner_uid", os.geteuid)
    monkeypatch.setattr(anchor, "_validate_service_uid", lambda _value: None)
    monkeypatch.setattr(anchor, "successor_activation_source_root", lambda _config: source_root)
    monkeypatch.setattr(anchor, "_mkdir_stage", _portable_mkdir)
    monkeypatch.setattr(anchor, "_rename_noreplace", _portable_rename_noreplace)

    recovery_path = Path(base.item.archives) / base.checkpoint.checkpoint_sha256
    kwargs = {
        "config_path": paths.config,
        "operator_consent_path": paths.consent,
        "legacy_signed_directive_path": paths.legacy,
        "initial_successor_page_path": paths.initial,
        "signed_host_artifact_path": paths.host,
        "worker_limits_path": paths.limits,
        "host_observer_config_path": paths.observer,
        "recovery_archive_path": recovery_path,
        "recovery_limits": base.item.limits,
        "verified_host_tree": host.tree,
        "verified_checkpoint": base.checkpoint,
    }
    item = SimpleNamespace(
        base=base,
        host=host,
        controls=controls,
        paths=paths,
        state_root=state_root,
        successor_root=successor_root,
        source_root=source_root,
        recovery_path=recovery_path,
        kwargs=kwargs,
    )
    yield item
    _restore_writable(state_root)
    _restore_writable(controls)
    _restore_writable(host.path)


def _materialize(case):
    return anchor.materialize_successor_anchor(**case.kwargs)


def test_materialize_restart_and_exact_root_owned_layout(anchor_case):
    case = anchor_case
    capability = _materialize(case)
    installed = case.source_root / activation.ANCHOR_DIRECTORY_NAME
    assert capability.source_root == case.source_root
    assert capability.config == case.base.config
    assert capability.operator_consent == case.base.consent
    assert capability.worker_execution_limits == case.base.limits
    assert capability.observer_config == case.base.observer_config
    assert capability.receipt.checkpoint_sha256 == case.base.receipt.checkpoint_sha256
    assert capability.receipt.host_manifest_sha256 == case.base.receipt.host_manifest_sha256
    assert capability.initial_state.accepted_directive_sha256 == case.base.signed.directive_sha256
    assert capability.recovery == case.base.checkpoint._body
    assert not capability.receipt.chain_submission_authorized
    assert not hasattr(capability, "authorization")
    assert set(path.name for path in installed.iterdir()) == set(anchor._ANCHOR_ENTRIES)
    assert installed.stat().st_mode & 0o777 == 0o555
    for name in anchor._ANCHOR_ENTRIES - {activation.RECOVERY_DIRECTORY_NAME}:
        assert (installed / name).stat().st_mode & 0o777 == 0o444
    recovery_root = installed / activation.RECOVERY_DIRECTORY_NAME
    for path in (recovery_root, *recovery_root.rglob("*")):
        expected = 0o555 if path.is_dir() else 0o444
        assert path.stat().st_mode & 0o777 == expected
    capability.recheck()
    restarted = anchor.load_materialized_successor_anchor(case.paths.config)
    assert restarted.receipt_sha256 == capability.receipt_sha256
    restarted.recheck()

    current = case.source_root / activation.CURRENT_DIRECTORY_NAME
    case.source_root.chmod(0o755)
    current.mkdir(mode=0o555)
    case.source_root.chmod(0o555)
    capability.recheck()


def test_anchor_is_never_replaced(anchor_case):
    case = anchor_case
    installed = case.source_root / activation.ANCHOR_DIRECTORY_NAME
    case.source_root.chmod(0o755)
    installed.mkdir(mode=0o755)
    sentinel = installed / "sentinel"
    sentinel.write_bytes(b"existing anchor")
    sentinel.chmod(0o444)
    installed.chmod(0o555)
    case.source_root.chmod(0o555)
    with pytest.raises(anchor.SuccessorAnchorError, match="not empty"):
        _materialize(case)
    assert sentinel.read_bytes() == b"existing anchor"


def test_injected_write_failure_leaves_only_an_inert_partial(anchor_case, monkeypatch):
    case = anchor_case

    def fail(*_args, **_kwargs):
        raise OSError("injected recovery write failure")

    monkeypatch.setattr(anchor, "_write_installed_recovery", fail)
    with pytest.raises(OSError, match="injected"):
        _materialize(case)
    entries = list(case.source_root.iterdir())
    assert len(entries) == 1
    assert entries[0].name.startswith(anchor.ANCHOR_STAGING_PREFIX)
    assert entries[0].stat().st_mode & 0o777 == 0o700
    assert not (case.source_root / activation.ANCHOR_DIRECTORY_NAME).exists()
    with pytest.raises(anchor.SuccessorAnchorError, match="unexpected entries"):
        anchor.load_materialized_successor_anchor(case.paths.config)


def test_source_modes_links_bounds_and_fixed_names_fail_closed(anchor_case):
    case = anchor_case
    case.paths.limits.chmod(0o666)
    with pytest.raises(anchor.SuccessorAnchorError, match="unsafe or oversized"):
        _materialize(case)
    case.paths.limits.chmod(0o400)

    hardlink = case.controls / "worker-limits-hardlink.json"
    os.link(case.paths.limits, hardlink)
    try:
        with pytest.raises(anchor.SuccessorAnchorError, match="unsafe or oversized"):
            _materialize(case)
    finally:
        hardlink.unlink()

    original_limits = case.paths.limits.read_bytes()
    case.paths.limits.chmod(0o600)
    case.paths.limits.write_bytes(b"x" * (activation.MAX_SUCCESSOR_WORKER_LIMITS_BYTES + 1))
    case.paths.limits.chmod(0o400)
    with pytest.raises(anchor.SuccessorAnchorError, match="unsafe or oversized"):
        _materialize(case)
    case.paths.limits.chmod(0o600)
    case.paths.limits.write_bytes(original_limits)
    case.paths.limits.chmod(0o400)

    wrong = case.paths.host.with_name("uploaded-host.json")
    case.paths.host.rename(wrong)
    case.kwargs["signed_host_artifact_path"] = wrong
    with pytest.raises(anchor.SuccessorAnchorError, match="wrong fixed filename"):
        _materialize(case)


def test_installed_control_and_recovery_tamper_invalidate_capability(anchor_case):
    case = anchor_case
    capability = _materialize(case)
    installed = capability.anchor_path
    installed.chmod(0o755)
    consent = installed / activation.OPERATOR_CONSENT_FILENAME
    consent.chmod(0o644)
    consent.write_bytes(consent.read_bytes() + b"\n")
    consent.chmod(0o444)
    installed.chmod(0o555)
    with pytest.raises(ValueError):
        capability.recheck()


def test_recovery_mode_tamper_and_capability_replacement_fail_closed(anchor_case):
    case = anchor_case
    capability = _materialize(case)
    forged = replace(capability, receipt_sha256="ab" * 32)
    with pytest.raises(anchor.SuccessorAnchorError, match="absent or altered"):
        forged.recheck()

    objects = (
        capability.anchor_path
        / activation.RECOVERY_DIRECTORY_NAME
        / capability.receipt.checkpoint_sha256
        / "objects"
    )
    target = next(objects.iterdir())
    target.chmod(0o400)
    with pytest.raises(ValueError):
        capability.recheck()


def test_explicit_parent_repair_loader_grants_no_normal_capability(anchor_case):
    case = anchor_case
    capability = _materialize(case)
    case.source_root.chmod(0o755)
    with pytest.raises(anchor.SuccessorAnchorError, match="owner or mode"):
        capability.recheck()
    capability.recheck_for_parent_repair()
    state = anchor.verify_materialized_current_history_for_repair(
        capability,
        case.base.current_page,
    )
    assert state.accepted_directive_sha256 == case.base.signed.directive_sha256
    with pytest.raises(anchor.SuccessorAnchorError, match="owner or mode"):
        anchor.load_materialized_successor_anchor(case.paths.config)
    repaired = anchor.load_materialized_successor_anchor_for_repair(case.paths.config)
    repaired.recheck_for_parent_repair()
    case.source_root.chmod(0o555)
    repaired.recheck()


def test_current_history_is_bound_to_the_sealed_initial_state(anchor_case):
    case = anchor_case
    capability = _materialize(case)
    state = anchor.verify_materialized_current_history(
        capability,
        case.base.current_page,
    )
    assert state.accepted_directive_sha256 == case.base.signed.directive_sha256
    wrong = case.base.current_page.model_copy(update={"after_directive_sha256": "ab" * 32})
    with pytest.raises(ValidatorSupervisorError):
        anchor.verify_materialized_current_history(capability, wrong)


def test_source_payload_change_during_seal_prevents_install(anchor_case, monkeypatch):
    case = anchor_case
    original = activation.seal_successor_installation_receipt

    def seal_then_change(*args, **kwargs):
        receipt = original(*args, **kwargs)
        case.paths.consent.chmod(0o600)
        case.paths.consent.write_bytes(canonical_json_bytes(case.base.consent) + b"\n")
        case.paths.consent.chmod(0o400)
        return receipt

    monkeypatch.setattr(activation, "seal_successor_installation_receipt", seal_then_change)
    with pytest.raises(anchor.SuccessorAnchorError, match="changed during materialization"):
        _materialize(case)
    assert not (case.source_root / activation.ANCHOR_DIRECTORY_NAME).exists()
