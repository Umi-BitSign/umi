"""Initial overlay authority survives native sealing and interrupted publication.

Only filesystem ownership/platform ports are replaced for the anchor and host
tree. Package replay, signatures, continuity, receipt and installed-capability
verification are native. This does not start systemd or execute a container.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_activation as activation
from umi import competition_host_anchor as anchor
from umi import competition_initial_upgrade as upgrade
from umi import competition_worker_maintenance as maintenance
from umi.competition_package import load_competition_package
from umi.competition_reward_continuity import (
    UNTIL_SUPERSEDED_BLOCK,
    RewardContinuation,
    RewardContinuityAuthority,
    RewardRecipientAmendment,
    admit_certified_allocation,
    sign_recipient_amendment,
    sign_reward_continuity_authority,
)
from umi.competition_supervisor import (
    SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SuccessorSupervisorDirectivePage,
    SuccessorSupervisorOperatorConsent,
    parse_canonical_successor_supervisor_directive_history,
    successor_initial_history_bytes,
    successor_operator_consent_sha256,
)
from umi.competition_weights import sign_competition_weight_authorization
from umi.competition_worker_overlay_scope import WorkerSourceOverlayScope
from umi.open_competition import Registration, digest
from umi.protocol import canonical_json_bytes

from .test_competition_host_activation import _replace_control, _weight_rollover, _write_control
from .test_competition_host_anchor import activation_case as activation_case
from .test_competition_host_anchor import anchor_case as anchor_case
from .test_competition_host_anchor import chain_config as chain_config
from .test_competition_host_anchor import explicit as explicit
from .test_competition_host_anchor import limits as limits
from .test_competition_host_anchor import package_limits as package_limits
from .test_competition_host_anchor import release_identity as release_identity
from .test_competition_host_anchor import replay_limits as replay_limits
from .test_competition_host_anchor import successor_release as successor_release
from .test_competition_host_anchor import trusted_ports as trusted_ports
from .test_competition_host_anchor import worker_capacity as worker_capacity
from .test_competition_host_artifacts import sign as sign_host
from .test_competition_recipient_amendment import base_policy as base_policy
from .test_competition_recipient_amendment import package_case as package_case
from .test_competition_recipient_amendment import policy as policy
from .test_competition_reward_continuity import fixture_boundary
from .test_competition_supervisor import _directive, _signed, _signed_authorization_target
from .test_validator_supervisor import _wallets as authority_wallets


def _file_bytes(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


def overlay_controls(base, package_limits, *, changed_scope_field=None):
    """Signed C4-style controls shared by portable and installed rehearsals."""
    package = load_competition_package(
        base.package.path,
        expected_package_sha256=base.target.package_sha256,
        expected_policy_sha256=base.target.policy_sha256,
        observed_release=base.release_identity,
        limits=package_limits,
    )
    wallets = authority_wallets()[:2]
    authority = sign_reward_continuity_authority(
        RewardContinuityAuthority(
            schema="umi-reward-continuity-authority/1",
            policy_sha256=base.target.policy_sha256,
            first_round_sha256=package.manifest.round_sha256,
            first_round_sequence=1,
            last_round_sequence=10,
            release_identity_sha256=base.target.release_identity_sha256,
            chain_pin=base.chain.chain_pin,
            issued_at_block=160,
            valid_from_block=160,
            lifetime="until_superseded_or_revoked",
            allocation_rule="latest_on_time_certified_exact_projection/1",
            recipient_change_action="hold_until_valid_certified_replacement",
            revocation_rule="stop_renewal_expire_outstanding_leases/1",
            admission_authority_hotkey=wallets[0].hotkey.ss58_address,
            maximum_write_authorization_blocks=100,
        ),
        wallets,
    )
    admission = admit_certified_allocation(authority, package, fixture_boundary(160), wallets[0])
    burn = package.policy.unallocated_model_burn
    recipient = next(
        a for a in package.retained_settlement.projection.allocations if a.uid != burn.uid
    )
    amendment = sign_recipient_amendment(
        RewardRecipientAmendment(
            schema="umi-reward-recipient-amendment/1",
            authority_sha256=digest(authority),
            package_sha256=package.package_sha256,
            projection_sha256=package.manifest.projection_sha256,
            issued_at_block=170,
            action="burn_listed_recipient_allocations/1",
            recipients=[Registration(uid=recipient.uid, hotkey=recipient.hotkey)],
            burn_destination=Registration(uid=burn.uid, hotkey=burn.hotkey),
        ),
        wallets,
    )
    continuation = RewardContinuation(
        schema="umi-reward-continuation/2",
        authority=authority,
        admission=admission,
        recipient_amendment=amendment,
    )
    rollover = _weight_rollover(base)
    chain = base.observer_config.chain
    rollover.body = rollover.body.model_copy(
        update={
            "required_finality_verifier_sha256_by_target": (
                chain.finality_pin.release_sha256_by_target
            ),
            "required_storage_proof_verifier_sha256_by_target": {
                chain.target_triple: chain.proof_binary_sha256,
            },
        }
    )
    rollover.execution = rollover.execution.model_copy(
        update={
            "weights": rollover.execution.weights.model_copy(update={"chain": chain}),
        }
    )
    authorization = sign_competition_weight_authorization(
        rollover.body.model_copy(
            update={
                "schema_": "umi-competition-weight-authorization/2",
                "continuation": continuation,
                "predecessor_directive_sha256": base.predecessor.signed.directive_sha256,
                "signed_at_block": 170,
                "valid_from_block": 175,
            }
        ),
        wallets[0],
    )
    scope = WorkerSourceOverlayScope(
        package_sha256=package.package_sha256,
        release_bundle_sha256=base.release_identity.release_bundle_sha256,
        recipient_amendment_sha256=digest(amendment),
    )
    if field := changed_scope_field:
        scope = scope.model_copy(update={field: "ff" * 32})
    consent = SuccessorSupervisorOperatorConsent.model_validate(
        {
            **base.consent.model_dump(by_alias=True),
            "reward_continuity_sha256": digest(authority),
            "valid_through_block": UNTIL_SUPERSEDED_BLOCK,
            "worker_source_overlay": scope,
        }
    )
    directive = _directive(
        base.predecessor,
        base.target,
        base.release,
        base.chain,
        consent,
        mode="competition_weights",
        sequence=base.predecessor.state.accepted_sequence + 1,
        issued_at_block=170,
        valid_from_block=175,
        valid_through_block=198,
        chain_authorization=_signed_authorization_target(authorization),
        reward_continuity_sha256=digest(authority),
    )
    signed = _signed(directive)
    initial = parse_canonical_successor_supervisor_directive_history(
        successor_initial_history_bytes(base.predecessor.signed, [signed])
    )
    current = SuccessorSupervisorDirectivePage(
        schema=SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_version=4,
        after_sequence=signed.directive.sequence,
        after_directive_sha256=signed.directive_sha256,
        directives=[],
        more=False,
        head=signed,
    )
    return SimpleNamespace(
        consent=consent,
        scope=scope,
        initial=initial,
        current=current,
        authorization=authorization,
        execution=rollover.execution,
    )


@pytest.fixture
def overlay_case(anchor_case, package_limits, monkeypatch, request):
    case = anchor_case
    controls = overlay_controls(
        case.base, package_limits, changed_scope_field=getattr(request, "param", None)
    )
    consent, initial = controls.consent, controls.initial
    _replace_control(case.paths.consent, consent)
    _replace_control(case.paths.initial, initial)
    case.controls.chmod(0o700)
    monkeypatch.setattr(maintenance, "_HOST_PARENT", case.host.path.parent)
    monkeypatch.setattr(activation, "ACTIVATION_MOUNT_ROOT", case.source_root)
    return SimpleNamespace(
        anchor=case,
        consent=consent,
        scope=controls.scope,
        current=controls.current,
        authorization=controls.authorization,
        execution=controls.execution,
    )


def _load_worker(case):
    """Publish inert current files, then use the real installed-input loader."""
    item = case.anchor
    current = item.source_root / activation.CURRENT_DIRECTORY_NAME
    item.source_root.chmod(0o755)
    shutil.copytree(item.base.current, current)
    item.source_root.chmod(0o555)
    _replace_control(current / activation.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME, case.current)
    _replace_control(current / activation.WORKER_EXECUTION_FILENAME, case.execution)
    current.chmod(0o755)
    _write_control(current / activation.WEIGHT_AUTHORIZATION_FILENAME, case.authorization, 0o444)
    current.chmod(0o555)
    return activation.load_successor_worker_inputs()


def _overlay(case, installation):
    return maintenance.approved_initial_worker_source_overlay(
        installation=installation,
        signed_host=case.anchor.host.signed,
    )


def _activation_view(installation):
    # source_for consumes these fields; installation and its full authorization
    # came from the native loader. This view grants no chain execution authority.
    return SimpleNamespace(
        _inputs=installation,
        package_sha256=installation.package_sha256,
        release_identity=installation.release_identity,
    )


def test_sealed_initial_overlay_survives_anchor_and_worker_restart(overlay_case):
    case = overlay_case
    item = case.anchor
    recovery_before = _file_bytes(item.recovery_path)
    package_before = _file_bytes(item.base.package.path)
    sealed = anchor.materialize_successor_anchor(**item.kwargs)
    installed_anchor = item.source_root / activation.ANCHOR_DIRECTORY_NAME
    consent_bytes = canonical_json_bytes(case.consent)
    assert (installed_anchor / activation.OPERATOR_CONSENT_FILENAME).read_bytes() == consent_bytes
    assert sealed.receipt.operator_consent_sha256 == successor_operator_consent_sha256(case.consent)
    before = _file_bytes(installed_anchor)
    first = _load_worker(case)
    reloaded_anchor = anchor.load_materialized_successor_anchor(item.paths.config)
    second = activation.load_successor_worker_inputs()
    assert first is not second
    assert reloaded_anchor.receipt == sealed.receipt
    assert second.operator_consent == case.consent
    for installation in (first, second):
        overlay = _overlay(case, installation)
        assert overlay.host_manifest_sha256 == item.host.signed.manifest_sha256
        assert overlay.root == item.host.path
        assert overlay.source_for(_activation_view(installation)) == item.host.path / "src/umi"
    assert _file_bytes(installed_anchor) == before
    assert _file_bytes(item.base.package.path) == package_before
    assert _file_bytes(item.recovery_path) == recovery_before
    retained = (
        installed_anchor / activation.RECOVERY_DIRECTORY_NAME / sealed.receipt.checkpoint_sha256
    )
    assert _file_bytes(retained) == recovery_before


@pytest.mark.parametrize(
    "overlay_case",
    [
        "package_sha256",
        "release_bundle_sha256",
        "recipient_amendment_sha256",
    ],
    indirect=True,
)
def test_sealed_overlay_cannot_authorize_a_different_worker(overlay_case):
    case = overlay_case
    anchor.materialize_successor_anchor(**case.anchor.kwargs)
    installation = _load_worker(case)
    overlay = _overlay(case, installation)
    with pytest.raises(ValueError, match="approved package or amendment"):
        overlay.source_for(_activation_view(installation))


def test_changed_sealed_consent_invalidates_live_capability_and_restart(overlay_case):
    case = overlay_case
    anchor.materialize_successor_anchor(**case.anchor.kwargs)
    installation = _load_worker(case)
    changed = case.consent.model_copy(
        update={
            "worker_source_overlay": case.scope.model_copy(update={"package_sha256": "ff" * 32}),
        }
    )
    path = (
        case.anchor.source_root
        / activation.ANCHOR_DIRECTORY_NAME
        / activation.OPERATOR_CONSENT_FILENAME
    )
    _replace_control(path, changed)
    with pytest.raises(activation.HostActivationError):
        _overlay(case, installation)
    with pytest.raises(activation.HostActivationError):
        activation.load_successor_worker_inputs()
    assert path.read_bytes() == canonical_json_bytes(changed)


def test_copied_installation_cannot_inject_overlay_authority(overlay_case):
    case = overlay_case
    anchor.materialize_successor_anchor(**case.anchor.kwargs)
    installation = _load_worker(case)
    changed = case.consent.model_copy(
        update={
            "worker_source_overlay": case.scope.model_copy(update={"package_sha256": "ff" * 32}),
        }
    )
    with pytest.raises(activation.HostActivationError, match="absent or altered"):
        _overlay(case, replace(installation, operator_consent=changed))
    assert _overlay(case, installation).scope == case.scope


@pytest.mark.parametrize("change", ["signatures", "revision"])
def test_valid_signed_host_must_match_exact_initial_receipt(overlay_case, change):
    case = overlay_case
    anchor.materialize_successor_anchor(**case.anchor.kwargs)
    installation = _load_worker(case)
    original = case.anchor.host.signed
    if change == "signatures":
        changed = original.model_copy(update={"signatures": list(reversed(original.signatures))})
        assert changed.manifest_sha256 == original.manifest_sha256
        assert len(canonical_json_bytes(changed)) == len(canonical_json_bytes(original))
    else:
        changed = sign_host(original.manifest.model_copy(update={"umi_git_revision": "43" * 20}))
    assert canonical_json_bytes(changed) != canonical_json_bytes(original)
    with pytest.raises(ValueError, match="sealed host receipt"):
        maintenance.approved_initial_worker_source_overlay(
            installation=installation,
            signed_host=changed,
        )
    assert _overlay(case, installation).root == case.anchor.host.path


@pytest.mark.parametrize("change", ["bytes", "symlink"])
def test_original_source_is_rechecked_before_factory_and_each_mount(overlay_case, change):
    case = overlay_case
    anchor.materialize_successor_anchor(**case.anchor.kwargs)
    installation = _load_worker(case)
    overlay = _overlay(case, installation)
    source = overlay.root / "src/umi/competition_supervisor.py"
    if change == "bytes":
        source.chmod(0o644)
        source.write_bytes(b"changed signed source")
        source.chmod(0o444)
    else:
        source.parent.chmod(0o755)
        source.unlink()
        source.symlink_to("competition_host_activation.py")
        source.parent.chmod(0o555)
    with pytest.raises(ValueError):
        _overlay(case, installation)
    with pytest.raises(ValueError):
        overlay.source_for(_activation_view(installation))


def _portable_rename(parent, source, destination, *, destination_parent=None):
    target = parent if destination_parent is None else destination_parent
    child = -1
    os.fchmod(parent, 0o755)
    try:
        try:
            os.stat(destination, dir_fd=target, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(destination)
        if target != parent:
            # Unprivileged macOS rename updates the moved directory's parent;
            # emulate root's ability to move the otherwise immutable stage.
            child = os.open(source, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
            os.fchmod(child, 0o755)
        os.rename(source, destination, src_dir_fd=parent, dst_dir_fd=target)
    finally:
        if child >= 0:
            os.fchmod(child, 0o555)
            os.close(child)
        os.fchmod(parent, 0o555)


@pytest.mark.parametrize("interruption", ["before_publish", "after_publish"])
def test_interrupted_anchor_publication_recovers_exact_sealed_overlay(
    overlay_case,
    monkeypatch,
    interruption,
):
    case = overlay_case
    item = case.anchor
    recovery_before = _file_bytes(item.recovery_path)
    controls_before = _file_bytes(item.controls)

    def interrupt(parent, source, destination):
        if interruption == "after_publish":
            _portable_rename(parent, source, destination)
        raise OSError("injected publication interruption")

    monkeypatch.setattr(anchor, "_rename_noreplace", interrupt)
    with pytest.raises(OSError, match="injected publication interruption"):
        anchor.materialize_successor_anchor(**item.kwargs)
    monkeypatch.setattr(anchor, "_rename_noreplace", _portable_rename)
    if interruption == "before_publish":
        with pytest.raises(anchor.SuccessorAnchorError):
            anchor.load_materialized_successor_anchor(item.paths.config)
        (partial,) = item.source_root.iterdir()
        assert partial.name.startswith(anchor.ANCHOR_STAGING_PREFIX)
        partial_before = _file_bytes(partial)
        monkeypatch.setattr(upgrade, "_require_root_linux", lambda: None)
        # macOS uid and primary gid differ. Precreate the root-owned retention
        # port with the exact identities the production helper will verify.
        retained = item.source_root.parent / "retained-anchors"
        retained.mkdir(mode=0o700)
        original_directory = upgrade._directory

        def directory(path, **kwargs):
            return original_directory(path, **{**kwargs, "group": os.getegid()})

        monkeypatch.setattr(upgrade, "_directory", directory)
        upgrade._retain_interrupted_anchors(item.base.config, SimpleNamespace(pw_uid=os.geteuid()))
        assert _file_bytes(retained / partial.name) == partial_before
        upgrade._retain_interrupted_anchors(item.base.config, SimpleNamespace(pw_uid=os.geteuid()))
        anchor.materialize_successor_anchor(**item.kwargs)
        assert _file_bytes(retained / partial.name) == partial_before
    else:
        before = _file_bytes(item.source_root / activation.ANCHOR_DIRECTORY_NAME)
        # Lost publication acknowledgement resumes by loading the sealed anchor;
        # attempting a fresh publication must never replace its receipt.
        with pytest.raises(anchor.SuccessorAnchorError, match="not empty"):
            anchor.materialize_successor_anchor(**item.kwargs)
        assert _file_bytes(item.source_root / activation.ANCHOR_DIRECTORY_NAME) == before
    reloaded = anchor.load_materialized_successor_anchor(item.paths.config)
    assert reloaded.operator_consent == case.consent
    installation = _load_worker(case)
    assert (
        _overlay(case, installation).source_for(_activation_view(installation))
        == item.host.path / "src/umi"
    )
    assert _file_bytes(item.controls) == controls_before
    assert _file_bytes(item.recovery_path) == recovery_before
