from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_activation as activation
from umi import competition_host_artifacts as artifacts
from umi import competition_recovery as recovery
from umi.competition_chain import CompetitionChainConfig
from umi.competition_package import prepare_competition_package
from umi.competition_supervisor import (
    SUCCESSOR_CHAIN_TARGET_SCHEMA,
    SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SuccessorSupervisorChainTarget,
    SuccessorSupervisorDirectivePage,
    successor_source_config_sha256,
)
from umi.competition_supervisor_observer import SuccessorHostObserverConfig
from umi.competition_weights import (
    CompetitionWeightAuthorizationBody,
    sign_competition_weight_authorization,
)
from umi.competition_worker_cli import (
    WORKER_CHAIN_SPEC,
    WORKER_FINALITY_BINARY,
    WORKER_FINALITY_STATE_ROOT,
    WORKER_PROOF_BINARY,
    SuccessorWeightExecutionConfig,
    SuccessorWorkerExecutionConfig,
)
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import (
    SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
    SupervisorDirectiveState,
    ValidatorSupervisorError,
)
from umi.validator_supervisor_worker import (
    SupervisorBootstrapAuthorizationClaim,
    SupervisorWorkerJournal,
)

from .test_competition_chain import chain_config as chain_config
from .test_competition_host_artifacts import sign as sign_host_artifact
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import _scenario
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_recovery import explicit as explicit
from .test_competition_recovery import limits as limits
from .test_competition_recovery import trusted_ports as trusted_ports
from .test_competition_supervisor import (
    _consent,
    _directive,
    _exact_package_target,
    _replace,
    _signed,
    _signed_authorization_target,
)
from .test_competition_supervisor import successor_release as successor_release
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import digest
from .test_open_competition import policy as policy
from .test_validator_supervisor import _config as v3_config
from .test_validator_supervisor import _directive as v3_directive
from .test_validator_supervisor import _signed as v3_signed
from .test_validator_supervisor import _wallets as authority_wallets


def _rewrite(path: Path, value) -> None:
    path.chmod(0o600)
    path.write_bytes(canonical_json_bytes(value))
    path.chmod(0o600)


def _adapt_recovery(item, config, signed) -> SupervisorDirectiveState:
    digest = signed.directive_sha256
    old = item.transaction
    new = old.parent / digest
    old.rename(new)
    journal_path = new / "journal.json"
    journal = SupervisorWorkerJournal.model_validate_json(journal_path.read_bytes(), strict=True)
    journal = journal.model_copy(
        update={
            "directive_sha256": digest,
            "sequence": signed.directive.sequence,
            "release_manifest_sha256": signed.directive.release.release_manifest_sha256,
        }
    )
    _rewrite(journal_path, journal)
    claim = SupervisorBootstrapAuthorizationClaim.model_validate_json(
        item.claim_path.read_bytes(), strict=True
    ).model_copy(update={"directive_sha256": digest, "sequence": signed.directive.sequence})
    _rewrite(item.claim_path, claim)
    config_sha256 = successor_source_config_sha256(config)
    item.transaction = new
    item.directive = digest
    item.kwargs.update(
        accepted_sequence=signed.directive.sequence,
        accepted_directive_sha256=digest,
        config_sha256=config_sha256,
    )
    item.stopped.accepted_sequence = signed.directive.sequence
    item.stopped.accepted_directive_sha256 = digest
    item.stopped.config_sha256 = config_sha256
    return SupervisorDirectiveState(
        schema=SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
        channel_id=config.channel_id,
        accepted_sequence=signed.directive.sequence,
        accepted_directive_sha256=digest,
        accepted_at_finalized_block=item.stopped.accepted_at_finalized_block,
        accepted_mode=signed.directive.mode,
        accepted_oci_manifest_sha256=signed.directive.release.oci_manifest_sha256,
        accepted_operator_input_sha256=signed.directive.operator_inputs.bundle_sha256,
    )


def _host_tree(tmp_path, monkeypatch, config):
    revision = "42" * 20
    parent = tmp_path / "host-stages"
    stage = parent / revision
    stage.mkdir(parents=True)
    files = []
    for name in sorted(artifacts._REQUIRED_FILES):
        path = stage / name
        path.parent.mkdir(parents=True, exist_ok=True)
        body = f"inert successor host file: {name}".encode()
        path.write_bytes(body)
        mode = 0o555 if name.startswith(".venv/bin/") else 0o444
        path.chmod(mode)
        files.append(
            artifacts.HostArtifactFile(
                path=name,
                sha256=hashlib.sha256(body).hexdigest(),
                size_bytes=len(body),
                mode=mode,
            )
        )
    for path in sorted(stage.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if path.is_dir():
            path.chmod(0o555)
    stage.chmod(0o555)
    manifest = artifacts.SuccessorHostArtifactManifest(
        schema=artifacts.HOST_ARTIFACT_SCHEMA,
        channel_id=config.channel_id,
        umi_git_revision=revision,
        target_platform=config.target_platform,
        host_entrypoint_profile="umi-competition-supervisor-host/1",
        total_size_bytes=sum(item.size_bytes for item in files),
        files=files,
    )
    signed = sign_host_artifact(manifest)
    monkeypatch.setattr(artifacts, "_STAGE_PARENT", parent)
    monkeypatch.setattr(artifacts, "_ancestor_paths", lambda _root: (parent,))
    monkeypatch.setattr(artifacts, "_current_platform", lambda: config.target_platform)
    original_owner = artifacts._immutable_owner
    monkeypatch.setattr(
        artifacts,
        "_immutable_owner",
        lambda info, mode, *, directory: original_owner(
            SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink),
            mode,
            directory=directory,
        ),
    )
    original_ancestor_owner = artifacts._ancestor_owner
    monkeypatch.setattr(
        artifacts,
        "_ancestor_owner",
        lambda info: original_ancestor_owner(SimpleNamespace(st_uid=0, st_mode=info.st_mode)),
    )
    tree = artifacts.verify_staged_host_tree(
        signed,
        config=config,
        expected_manifest_sha256=signed.manifest_sha256,
        stage_root=stage,
    )
    return SimpleNamespace(path=stage, signed=signed, tree=tree)


def _write_control(path: Path, value, mode: int = 0o400) -> bytes:
    payload = value if isinstance(value, bytes) else canonical_json_bytes(value)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)
    return payload


def _restore_writable(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if not path.is_symlink():
            path.chmod(0o700 if path.is_dir() else 0o600)
    root.chmod(0o700)


def _replace_control(path: Path, value) -> None:
    parent = path.parent
    parent.chmod(0o755)
    path.chmod(0o644)
    path.write_bytes(value if isinstance(value, bytes) else canonical_json_bytes(value))
    path.chmod(0o444)
    parent.chmod(0o555)


def _weight_rollover(case):
    target_triple = case.release_identity.target_triple
    finality = case.chain_config.finality_pin.model_copy(
        update={"release_sha256_by_target": {target_triple: "24" * 32}}
    )
    values = case.chain_config.model_dump(mode="python", by_alias=True)
    values.update(
        {
            "policy_sha256": case.target.policy_sha256,
            "finality_pin": finality,
            "target_triple": target_triple,
            "finality_binary": str(WORKER_FINALITY_BINARY),
            "chain_spec": str(WORKER_CHAIN_SPEC),
            "proof_binary": str(WORKER_PROOF_BINARY),
            "proof_binary_sha256": "25" * 32,
            "state_directory": str(WORKER_FINALITY_STATE_ROOT),
        }
    )
    chain_config = CompetitionChainConfig.model_validate(values)
    body = CompetitionWeightAuthorizationBody(
        schema="umi-competition-weight-authorization/1",
        authorization_id="19" * 32,
        validator_scope="any_permitted_sn78",
        policy_sha256=case.target.policy_sha256,
        package_sha256=case.target.package_sha256,
        settlement_sha256=case.target.settlement_sha256,
        projection_sha256=case.target.projection_sha256,
        release_identity_sha256=case.target.release_identity_sha256,
        predecessor_directive_sha256=case.signed.directive_sha256,
        required_recovery_profile="stopped_bootstrap_recovery/1",
        chain_pin=case.chain.chain_pin,
        required_finality_verifier_sha256_by_target={target_triple: "24" * 32},
        required_storage_proof_verifier_sha256_by_target={target_triple: "25" * 32},
        network="finney",
        netuid=78,
        mechanism_id=0,
        signed_at_block=190,
        valid_from_block=192,
        valid_through_block=200,
        weights_version_key=1,
        required_min_allowed_weights=1,
        required_max_allowed_uids=256,
        required_max_weights_limit=65535,
        required_weights_rate_limit=0,
        required_mechanism_count=1,
        required_commit_reveal_enabled=False,
        mortality_period=4,
        late_conflict_action="hold_no_automatic_correction",
    )
    authorization = sign_competition_weight_authorization(body, authority_wallets()[0])
    authorization_target = _signed_authorization_target(authorization)
    draft = _directive(
        case.predecessor,
        case.target,
        case.release,
        case.chain,
        case.consent,
        mode="competition_weights",
        sequence=4,
        predecessor_version=4,
        previous=case.signed.directive_sha256,
        issued_at_block=190,
        valid_from_block=193,
        valid_through_block=198,
    )
    directive = _replace(draft, chain_authorization=authorization_target)
    signed = _signed(directive)
    page = SuccessorSupervisorDirectivePage(
        schema=SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_version=4,
        after_sequence=case.signed.directive.sequence,
        after_directive_sha256=case.signed.directive_sha256,
        directives=[signed],
        more=False,
        head=signed,
    )
    execution = SuccessorWorkerExecutionConfig(
        schema="umi-successor-worker-execution-config/1",
        replay_capacity=case.execution.replay_capacity,
        weights=SuccessorWeightExecutionConfig(
            maximum_attempts=20,
            maximum_evidence_bytes=50_000_000,
            submission_timeout_seconds=30,
            chain=chain_config,
        ),
    )
    return SimpleNamespace(
        body=body,
        authorization=authorization,
        directive=directive,
        signed=signed,
        page=page,
        execution=execution,
    )


def _install_weight_rollover(case, rollover) -> None:
    _replace_control(
        case.current / activation.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
        rollover.page,
    )
    _replace_control(
        case.current / activation.WORKER_EXECUTION_FILENAME,
        rollover.execution,
    )
    case.current.chmod(0o755)
    _write_control(
        case.current / activation.WEIGHT_AUTHORIZATION_FILENAME,
        rollover.authorization,
        0o444,
    )
    case.current.chmod(0o555)


@pytest.fixture
def activation_case(
    tmp_path,
    monkeypatch,
    trusted_ports,
    package_case,
    package_limits,
    release_identity,
    policy,
    successor_release,
    worker_capacity,
    chain_config,
):
    item = trusted_ports
    item.observation.genesis_hash = "0x" + FINNEY_GENESIS_HASH
    config = v3_config(validator_hotkey=item.auth.validator_hotkey)
    legacy_directive = v3_directive(
        sequence=2,
        previous_directive_sha256="90" * 32,
        validator_hotkeys=[item.auth.validator_hotkey],
        valid_through_block=1_000,
    )
    legacy_signed = v3_signed(legacy_directive)
    v3_state = _adapt_recovery(item, config, legacy_signed)
    prepared = recovery.prepare_recovery_checkpoint(
        item.stopped,
        item.observation,
        destination_root=item.archives,
        limits=item.limits,
    )
    checkpoint = recovery.verify_recovery_checkpoint(
        Path(prepared.checkpoint_path),
        expected_checkpoint_sha256=prepared.checkpoint_sha256,
        stopped=item.stopped,
        observation=item.observation,
        limits=item.limits,
    )
    host = _host_tree(tmp_path, monkeypatch, config)
    predecessor = SimpleNamespace(
        config=config,
        signed=legacy_signed,
        body=canonical_json_bytes(legacy_signed),
        state=v3_state,
    )
    consent = _consent(
        predecessor,
        approved_host_manifest_sha256=host.signed.manifest_sha256,
        authorized_at_finalized_block=170,
        valid_through_block=1_000,
    )
    target = _exact_package_target(package_case, package_limits, policy)
    chain = SuccessorSupervisorChainTarget(
        schema=SUCCESSOR_CHAIN_TARGET_SCHEMA,
        network="finney",
        netuid=78,
        mechanism_id=0,
        chain_pin=chain_config.chain_pin,
    )
    directive = _directive(
        predecessor,
        target,
        successor_release,
        chain,
        consent,
        sequence=3,
        issued_at_block=170,
        valid_from_block=175,
        valid_through_block=260,
    )
    signed = _signed(directive)
    initial_page = SuccessorSupervisorDirectivePage(
        schema=SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_version=3,
        after_sequence=v3_state.accepted_sequence,
        after_directive_sha256=v3_state.accepted_directive_sha256,
        directives=[signed],
        more=False,
        head=signed,
    )
    current_page = SuccessorSupervisorDirectivePage(
        schema=SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_version=4,
        after_sequence=signed.directive.sequence,
        after_directive_sha256=signed.directive_sha256,
        directives=[],
        more=False,
        head=signed,
    )
    limits_value = activation.SuccessorWorkerExecutionLimits(
        schema="umi-successor-worker-execution-limits/1",
        replay_capacity_ceiling=worker_capacity,
        maximum_weight_attempts=20,
        maximum_weight_evidence_bytes=50_000_000,
        maximum_submission_timeout_seconds=30,
    )
    execution = SuccessorWorkerExecutionConfig(
        schema="umi-successor-worker-execution-config/1",
        replay_capacity=worker_capacity,
        weights=None,
    )
    target_triple = release_identity.target_triple
    observer_finality = chain_config.finality_pin.model_copy(
        update={"release_sha256_by_target": {target_triple: "24" * 32}}
    )
    observer_chain = CompetitionChainConfig.model_validate(
        {
            **chain_config.model_dump(mode="python", by_alias=True),
            "finality_pin": observer_finality,
            "target_triple": target_triple,
            "finality_binary": str(WORKER_FINALITY_BINARY),
            "chain_spec": str(WORKER_CHAIN_SPEC),
            "proof_binary": str(WORKER_PROOF_BINARY),
            "proof_binary_sha256": "25" * 32,
            "state_directory": str(WORKER_FINALITY_STATE_ROOT),
        }
    )
    observer_config = SuccessorHostObserverConfig(
        schema="umi-successor-host-observer-config/1",
        policy=policy,
        chain=observer_chain,
    )
    controls = tmp_path / "seal-controls"
    paths = SimpleNamespace(
        config=controls / activation.SOURCE_CONFIG_FILENAME,
        consent=controls / activation.OPERATOR_CONSENT_FILENAME,
        legacy=controls / activation.LEGACY_SIGNED_DIRECTIVE_FILENAME,
        initial=controls / activation.INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
        host=controls / activation.SIGNED_HOST_ARTIFACT_FILENAME,
        worker_limits=controls / activation.WORKER_LIMITS_FILENAME,
        observer=controls / activation.HOST_OBSERVER_FILENAME,
        receipt=controls / activation.INSTALLATION_RECEIPT_FILENAME,
    )
    _write_control(paths.config, config)
    _write_control(paths.consent, consent)
    _write_control(paths.legacy, legacy_signed)
    _write_control(paths.initial, initial_page)
    _write_control(paths.host, host.signed)
    _write_control(paths.worker_limits, limits_value)
    _write_control(paths.observer, observer_config)
    monkeypatch.setattr(activation, "_require_root_linux", lambda: None)
    monkeypatch.setattr(activation, "_root_owner_uid", os.geteuid)
    receipt = activation.seal_successor_installation_receipt(
        paths.receipt,
        config_path=paths.config,
        operator_consent_path=paths.consent,
        legacy_signed_directive_path=paths.legacy,
        initial_successor_page_path=paths.initial,
        signed_host_artifact_path=paths.host,
        worker_limits_path=paths.worker_limits,
        host_observer_config_path=paths.observer,
        recovery_archive_path=Path(prepared.checkpoint_path),
        recovery_limits=item.limits,
        verified_host_tree=host.tree,
        verified_checkpoint=checkpoint,
    )
    mount = tmp_path / "activation-mount"
    anchor = mount / activation.ANCHOR_DIRECTORY_NAME
    current = mount / activation.CURRENT_DIRECTORY_NAME
    anchor.mkdir(parents=True)
    current.mkdir()
    for path in (
        paths.config,
        paths.consent,
        paths.legacy,
        paths.initial,
        paths.host,
        paths.worker_limits,
        paths.observer,
        paths.receipt,
    ):
        shutil.copyfile(path, anchor / path.name)
        (anchor / path.name).chmod(0o444)
    recovery_root = anchor / activation.RECOVERY_DIRECTORY_NAME
    recovery_root.mkdir()
    shutil.copytree(
        prepared.checkpoint_path,
        recovery_root / prepared.checkpoint_sha256,
    )
    for path in (recovery_root / prepared.checkpoint_sha256).rglob("*"):
        path.chmod(0o555 if path.is_dir() else 0o444)
    (recovery_root / prepared.checkpoint_sha256).chmod(0o555)
    _write_control(
        current / activation.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
        current_page,
        0o444,
    )
    _write_control(
        current / activation.RELEASE_IDENTITY_FILENAME,
        release_identity,
        0o444,
    )
    _write_control(current / activation.WORKER_EXECUTION_FILENAME, execution, 0o444)
    shutil.copytree(package_case.path, current / activation.PACKAGE_DIRECTORY_NAME)
    recovery_root.chmod(0o555)
    anchor.chmod(0o555)
    current.chmod(0o555)
    mount.chmod(0o555)
    monkeypatch.setattr(activation, "ACTIVATION_MOUNT_ROOT", mount)
    monkeypatch.setattr(activation, "_require_readonly_filesystem", lambda _path: None)
    monkeypatch.setattr(activation, "_valid_anchor_mount_owner", lambda _owner: True)
    case = SimpleNamespace(
        item=item,
        config=config,
        predecessor=predecessor,
        consent=consent,
        target=target,
        chain=chain,
        release=successor_release,
        directive=directive,
        signed=signed,
        initial_page=initial_page,
        current_page=current_page,
        limits=limits_value,
        execution=execution,
        observer_config=observer_config,
        receipt=receipt,
        checkpoint=checkpoint,
        package=package_case,
        release_identity=release_identity,
        mount=mount,
        anchor=anchor,
        current=current,
        chain_config=chain_config,
    )
    yield case
    _restore_writable(mount)
    _restore_writable(host.path)
    _restore_writable(controls)


def test_seal_restart_load_and_wallet_free_activation(activation_case):
    case = activation_case
    observer_bytes = (case.anchor / activation.HOST_OBSERVER_FILENAME).read_bytes()
    parsed = activation.parse_canonical_successor_installation_receipt(
        (case.anchor / activation.INSTALLATION_RECEIPT_FILENAME).read_bytes()
    )
    assert parsed == case.receipt
    assert parsed.host_observer_config_sha256 == hashlib.sha256(observer_bytes).hexdigest()
    assert parsed.host_observer_config_size_bytes == len(observer_bytes)
    inputs = activation.load_successor_worker_inputs()
    activation.validate_authenticated_successor_installation(inputs)
    inputs.recheck()
    assert inputs.profile == "competition_replay"
    assert inputs.mount_root == case.mount
    assert inputs.directive_sha256 == case.signed.directive_sha256
    assert inputs.observer_config == case.observer_config
    assert inputs.initial_accepted_at_finalized_block == case.checkpoint.finalized_block
    assert not hasattr(inputs, "chain_submission_authorized")

    active = activation.activate_successor_worker(inputs)
    activation.validate_authenticated_successor_activation(
        active,
        validator_hotkey=inputs.validator_hotkey,
        directive_sha256=inputs.directive_sha256,
        package_sha256=inputs.package_sha256,
        authorization_sha256=None,
        expected_profile="competition_replay",
    )
    retained = active.validate_retained_recovery(
        inputs.checkpoint_sha256,
        inputs.validator_hotkey,
        inputs.directive.previous_directive_sha256,
    )
    assert retained.legacy_predecessor_directive_sha256 == (
        case.predecessor.state.accepted_directive_sha256
    )


def test_initial_observer_config_is_bound_to_transition_chain_and_platform(activation_case):
    case = activation_case
    opposite_target = "aarch64-unknown-linux-gnu"
    finality = case.observer_config.chain.finality_pin.model_copy(
        update={"release_sha256_by_target": {opposite_target: "32" * 32}}
    )
    opposite = case.observer_config.model_copy(
        update={
            "chain": case.observer_config.chain.model_copy(
                update={"target_triple": opposite_target, "finality_pin": finality}
            )
        }
    )
    with pytest.raises(activation.HostActivationError, match="chain or platform"):
        activation._verify_host_observer_config(
            opposite,
            config=case.config,
            checkpoint_genesis_hash=case.receipt.checkpoint_genesis_hash,
        )
    with pytest.raises(activation.HostActivationError, match="chain or platform"):
        activation._verify_host_observer_config(
            case.observer_config,
            config=case.config,
            checkpoint_genesis_hash="0x" + "34" * 32,
        )


def test_capabilities_cannot_be_replaced_or_rebound(activation_case):
    inputs = activation.load_successor_worker_inputs()
    with pytest.raises(activation.HostActivationError, match="absent or altered"):
        activation.validate_authenticated_successor_installation(
            replace(inputs, receipt_sha256="00" * 32)
        )
    active = activation.activate_successor_worker(inputs)
    with pytest.raises(activation.HostActivationError, match="absent or altered"):
        replace(active, package_sha256="00" * 32).recheck()


def test_verified_inputs_do_not_replay_or_reload_recovery_after_load(activation_case, monkeypatch):
    inputs = activation.load_successor_worker_inputs()

    def forbidden(*_args, **_kwargs):
        pytest.fail("verified immutable inputs must not replay after proof capture")

    monkeypatch.setattr(activation, "load_bound_successor_replay_package", forbidden)
    monkeypatch.setattr(activation, "load_installed_retained_checkpoint_archive", forbidden)
    activation.validate_authenticated_successor_installation(inputs)
    inputs.recheck()
    active = activation.activate_successor_worker(inputs)
    active.recheck()
    active.validate_retained_recovery(
        inputs.checkpoint_sha256,
        inputs.validator_hotkey,
        inputs.directive.previous_directive_sha256,
    )


@pytest.mark.parametrize(
    "fault",
    ["same_size_edit", "restored_bytes", "replacement", "symlink", "hardlink", "fifo", "mode"],
)
def test_verified_snapshot_rejects_changes_even_with_restored_mtime(
    activation_case, fault, tmp_path
):
    inputs = activation.load_successor_worker_inputs()
    active = activation.activate_successor_worker(inputs)
    path = activation_case.current / "package" / "policy.json"
    before = path.stat()
    content = path.read_bytes()
    if fault in {"same_size_edit", "restored_bytes", "mode"}:
        path.chmod(0o600)
        if fault != "mode":
            path.write_bytes(b"x" * len(content))
            if fault == "restored_bytes":
                path.write_bytes(content)
            path.chmod(before.st_mode & 0o777)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    else:
        parent_mode = path.parent.stat().st_mode & 0o777
        path.parent.chmod(0o700)
        outside = tmp_path / "alternate-policy"
        outside.write_bytes(content)
        outside.chmod(before.st_mode & 0o777)
        path.unlink()
        if fault == "replacement":
            path.write_bytes(content)
            path.chmod(before.st_mode & 0o777)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        elif fault == "symlink":
            path.symlink_to(outside)
        elif fault == "hardlink":
            os.link(outside, path)
        else:
            os.mkfifo(path, mode=0o400)
        path.parent.chmod(parent_mode)
    with pytest.raises(activation.HostActivationError):
        active.recheck()


def test_mutation_during_full_replay_cannot_mint_snapshot(activation_case, monkeypatch):
    replay = activation.load_bound_successor_replay_package

    def mutate_after_verification(*args, **kwargs):
        package = replay(*args, **kwargs)
        path = activation_case.current / "package" / "policy.json"
        before = path.stat()
        body = path.read_bytes()
        path.chmod(0o600)
        path.write_bytes(b"x" * len(body))
        path.write_bytes(body)
        path.chmod(before.st_mode & 0o777)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return package

    monkeypatch.setattr(
        activation, "load_bound_successor_replay_package", mutate_after_verification
    )
    with pytest.raises(activation.HostActivationError, match="changed during verification"):
        activation.load_successor_worker_inputs()


def test_snapshot_cannot_be_rebound_to_changed_tree(activation_case):
    inputs = activation.load_successor_worker_inputs()
    path = activation_case.current / "package" / "policy.json"
    path.chmod(0o600)
    path.write_bytes(b"x" * path.stat().st_size)
    path.chmod(0o400)
    changed = activation._snapshot_mounted_tree(inputs.mount_root, inputs._receipt.recovery_limits)
    rebound = replace(inputs, _mount=replace(inputs._mount, tree_snapshot=changed))
    with pytest.raises(activation.HostActivationError, match="absent or altered"):
        rebound.recheck()


@pytest.mark.parametrize(
    "subtree,filename",
    [
        ("anchor", activation.INSTALLATION_RECEIPT_FILENAME),
        ("anchor", activation.SOURCE_CONFIG_FILENAME),
        ("anchor", activation.OPERATOR_CONSENT_FILENAME),
        ("anchor", activation.LEGACY_SIGNED_DIRECTIVE_FILENAME),
        ("anchor", activation.INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME),
        ("anchor", activation.SIGNED_HOST_ARTIFACT_FILENAME),
        ("anchor", activation.WORKER_LIMITS_FILENAME),
        ("anchor", activation.HOST_OBSERVER_FILENAME),
        ("current", activation.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME),
        ("current", activation.RELEASE_IDENTITY_FILENAME),
        ("current", activation.WORKER_EXECUTION_FILENAME),
    ],
)
def test_control_tamper_is_rejected(activation_case, subtree, filename):
    root = getattr(activation_case, subtree)
    path = root / filename
    _replace_control(path, path.read_bytes() + b"\n")
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        activation.load_successor_worker_inputs()


def test_links_unknown_entries_and_bounds_are_rejected(activation_case, tmp_path):
    case = activation_case
    page = case.current / activation.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME
    outside = tmp_path / "outside-page"
    outside.write_bytes(page.read_bytes())
    outside.chmod(0o444)
    case.current.chmod(0o755)
    page.unlink()
    page.symlink_to(outside)
    case.current.chmod(0o555)
    with pytest.raises(ValueError):
        activation.load_successor_worker_inputs()


def test_oversized_current_page_rejected_before_json_parse(activation_case):
    path = activation_case.current / activation.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME
    _replace_control(path, b"x" * (activation.MAX_SUCCESSOR_DOCUMENT_BYTES + 1))
    with pytest.raises(activation.HostActivationError, match="oversized"):
        activation.load_successor_worker_inputs()


def test_package_and_retained_archive_tamper_fail_closed(activation_case):
    inputs = activation.load_successor_worker_inputs()
    package_file = activation_case.current / activation.PACKAGE_DIRECTORY_NAME / "policy.json"
    package_file.chmod(0o600)
    package_file.write_bytes(b"x" * package_file.stat().st_size)
    package_file.chmod(0o400)
    with pytest.raises(ValueError):
        inputs.recheck()

    # The immutable installation validator independently reloads recovery.
    archive = (
        activation_case.anchor
        / activation.RECOVERY_DIRECTORY_NAME
        / inputs.checkpoint_sha256
        / "checkpoint.json"
    )
    archive.chmod(0o600)
    archive.write_bytes(b"x" * archive.stat().st_size)
    archive.chmod(0o444)
    with pytest.raises(ValueError):
        activation.validate_authenticated_successor_installation(inputs)


def test_rolling_config_cannot_exceed_root_sealed_ceiling(activation_case):
    case = activation_case
    capacity = case.execution.replay_capacity.model_copy(
        update={"maximum_receipts": case.limits.replay_capacity_ceiling.maximum_receipts + 1}
    )
    execution = case.execution.model_copy(update={"replay_capacity": capacity})
    _replace_control(case.current / activation.WORKER_EXECUTION_FILENAME, execution)
    with pytest.raises(activation.HostActivationError, match="exceeds installed ceilings"):
        activation.load_successor_worker_inputs()


def test_later_weight_page_uses_owned_head_without_resealing_root_anchor(
    activation_case, monkeypatch
):
    case = activation_case
    original = activation.load_successor_worker_inputs()
    rollover = _weight_rollover(case)
    assert rollover.directive.issued_at_block > case.receipt.checkpoint_finalized_block
    _install_weight_rollover(case, rollover)

    # A runtime lease authenticates only the original stopped transition. It
    # survives a service-owned rolling snapshot change, while the old worker
    # snapshot capability detects the change.
    activation.validate_authenticated_successor_installation(original)
    with pytest.raises(activation.HostActivationError):
        original.recheck()

    inputs = activation.load_successor_worker_inputs()
    assert inputs.profile == "competition_weights"
    assert inputs.directive_sha256 == rollover.signed.directive_sha256
    assert inputs.authorization == rollover.authorization
    with pytest.raises(activation.HostActivationError, match="owned finalized observation"):
        activation.activate_successor_worker(inputs)

    observation = SimpleNamespace(
        validator_hotkey=inputs.validator_hotkey,
        genesis_hash=case.receipt.checkpoint_genesis_hash,
        block=195,
        block_hash="0x" + "21" * 32,
    )
    from umi import competition_chain_state

    monkeypatch.setattr(
        competition_chain_state,
        "validate_owned_weight_observation",
        lambda value: (
            None if value is observation else (_ for _ in ()).throw(ValueError("not owned"))
        ),
    )
    active = activation.activate_successor_worker(inputs, owned_observation=observation)
    assert active.accepted_state.accepted_sequence == 4
    assert active.finalized_block == 195
    active.validate_retained_recovery(
        inputs.checkpoint_sha256,
        inputs.validator_hotkey,
        rollover.directive.previous_directive_sha256,
    )
    with pytest.raises(activation.HostActivationError, match="binding changed"):
        active.validate_retained_recovery(
            inputs.checkpoint_sha256,
            inputs.validator_hotkey,
            case.predecessor.state.accepted_directive_sha256,
        )


def test_new_signed_policy_and_package_roll_without_new_root_receipt(
    activation_case, policy, replay_limits, package_limits, tmp_path
):
    case = activation_case
    original = activation.load_successor_worker_inputs()
    policy_values = policy.model_dump(mode="python", by_alias=True)
    policy_values.update(sequence=2, predecessor_sha256=digest(policy))
    next_policy = type(policy).model_validate(policy_values)
    scenario = _scenario(next_policy, tmp_path / "next-scenario", replay_limits)
    prepared = prepare_competition_package(
        policy=next_policy,
        cutoff_certificate=scenario.cutoff_certificate,
        settlement_certificate=scenario.settlement_certificate,
        retained_settlement=scenario.settlement,
        roster=scenario.submissions,
        evidence=scenario.evidence,
        replay_limits=replay_limits,
        release_identity=case.release_identity,
        destination_root=tmp_path / "next-packages",
        limits=package_limits,
    )
    package_path = Path(prepared.package_path)
    package_case = SimpleNamespace(path=package_path, prepared=prepared)
    target = _exact_package_target(package_case, package_limits, next_policy)
    directive = _directive(
        case.predecessor,
        target,
        case.release,
        case.chain,
        case.consent,
        sequence=4,
        predecessor_version=4,
        previous=case.signed.directive_sha256,
        issued_at_block=190,
        valid_from_block=195,
        valid_through_block=260,
    )
    signed = _signed(directive)
    page = SuccessorSupervisorDirectivePage(
        schema=SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_version=4,
        after_sequence=case.signed.directive.sequence,
        after_directive_sha256=case.signed.directive_sha256,
        directives=[signed],
        more=False,
        head=signed,
    )
    _replace_control(
        case.current / activation.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
        page,
    )
    mounted_package = case.current / activation.PACKAGE_DIRECTORY_NAME
    case.current.chmod(0o755)
    try:
        _restore_writable(mounted_package)
        shutil.rmtree(mounted_package)
        shutil.copytree(package_path, mounted_package)
    finally:
        case.current.chmod(0o555)
    try:
        activation.validate_authenticated_successor_installation(original)
        with pytest.raises(activation.HostActivationError):
            original.recheck()
        renewed = activation.load_successor_worker_inputs()
        assert renewed.receipt_sha256 == original.receipt_sha256
        assert renewed.directive.replay_package.policy_sha256 == digest(next_policy)
        assert renewed.package_sha256 == prepared.package_sha256
    finally:
        _restore_writable(package_path)
