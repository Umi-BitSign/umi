from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_evidence_activation as switch
from umi import competition_host_activation as activation
from umi.competition_evidence_migration_models import EvidenceMigrationSeal
from umi.competition_history_compatibility import HistoryCompatibilityBody, original_consent_digest
from umi.competition_supervisor import SuccessorSupervisorOperatorConsent
from umi.protocol import canonical_json_bytes

from .test_competition_evidence_config import storage_config
from .test_competition_history_compatibility import digest, sign
from .test_competition_host_activation import (
    _install_weight_rollover,
    _replace_control,
    _restore_writable,
    _weight_rollover,
)
from .test_competition_host_activation import (
    activation_case as activation_case,
)
from .test_competition_host_activation import (
    chain_config as chain_config,
)
from .test_competition_host_activation import (
    explicit as explicit,
)
from .test_competition_host_activation import (
    limits as limits,
)
from .test_competition_host_activation import (
    package_case as package_case,
)
from .test_competition_host_activation import (
    package_limits as package_limits,
)
from .test_competition_host_activation import (
    policy as policy,
)
from .test_competition_host_activation import (
    release_identity as release_identity,
)
from .test_competition_host_activation import (
    replay_limits as replay_limits,
)
from .test_competition_host_activation import (
    successor_release as successor_release,
)
from .test_competition_host_activation import (
    trusted_ports as trusted_ports,
)
from .test_competition_host_activation import (
    worker_capacity as worker_capacity,
)
from .test_competition_weights import _advance
from .test_competition_weights import chain as chain
from .test_competition_weights import weight_case as weight_case


@pytest.fixture
def migrated(activation_case, tmp_path, request):
    c = activation_case
    if getattr(request, "param", None) == "weights":
        _install_weight_rollover(c, _weight_rollover(c))
    installed = activation.load_successor_worker_inputs()
    prior = installed.accepted_state
    target = c.consent.model_copy(
        update={"approved_host_manifest_sha256": "ad" * 32, "authorized_at_finalized_block": 190}
    )
    limits = c.limits.model_copy(
        update={
            "schema_": "umi-successor-worker-execution-limits/2",
            "weight_evidence_storage": storage_config(),
        }
    )
    body = HistoryCompatibilityBody(
        schema="umi-successor-history-compatibility/1",
        source_config_sha256=digest(c.config),
        channel_id=c.config.channel_id,
        validator_hotkey=c.config.validator_hotkey,
        target_platform=c.config.target_platform,
        chain_pin_sha256=digest(c.chain.chain_pin),
        original_consent_sha256=original_consent_digest(c.consent),
        target_consent_sha256=original_consent_digest(target),
        original_installation_receipt_sha256=digest(c.receipt),
        original_host_manifest_sha256=c.receipt.host_manifest_sha256,
        target_host_manifest_sha256=target.approved_host_manifest_sha256,
        original_worker_limits_sha256=digest(c.limits),
        target_worker_limits_sha256=digest(limits),
        original_checkpoint_sha256=c.receipt.checkpoint_sha256,
        retained_history_sha256=digest(
            [
                item.model_dump(mode="json", by_alias=True)
                for item in [*installed.initial_page.directives, *installed.current_page.directives]
            ]
        ),
        predecessor_state_sha256=digest(prior),
        predecessor_sequence=prior.accepted_sequence,
        predecessor_directive_sha256=prior.accepted_directive_sha256,
        predecessor_accepted_at_finalized_block=prior.accepted_at_finalized_block,
        original_release_identity_sha256s=[c.target.release_identity_sha256],
        target_release_identity_sha256="03" * 32,
        target_oci_manifest_sha256="04" * 32,
        target_source_tree_sha256="05" * 32,
        target_storage_config_sha256=digest(storage_config()),
        first_round_sequence=c.target.round_sequence + 1,
        last_round_sequence=c.target.round_sequence + 6,
        forward_policy_sha256s=[c.target.policy_sha256],
        migration_valid_from_block=190,
        migration_valid_through_block=250,
        minimum_transition_headroom_blocks=10,
        historical_use="verification_and_stopped_recovery_only",
    )
    consent = SuccessorSupervisorOperatorConsent.model_validate(
        {
            **target.model_dump(by_alias=True),
            "schema": "umi-validator-supervisor-operator-consent/2",
            "historical_consent": c.consent,
            "history_compatibility": sign(body),
        }
    )
    preparation = dict(
        schema="umi-weight-evidence-preparation/1",
        source_root=str(tmp_path / "source-db"),
        candidate_root=str(tmp_path / "candidate-db"),
        source_database_sha256="06" * 32,
        candidate_database_sha256="07" * 32,
        maximum_database_bytes=storage_config().maximum_database_bytes,
        worker_profile_sha256=hashlib.sha256(storage_config().profile().encoded()).hexdigest(),
        source_selection_changed=False,
        activation_authorized=False,
        root_sealed=False,
    )
    seal = EvidenceMigrationSeal(
        schema="umi-weight-evidence-migration-seal/1",
        compatibility_sha256=digest(consent.history_compatibility),
        original_receipt_hex=canonical_json_bytes(c.receipt).hex(),
        original_worker_limits_hex=canonical_json_bytes(c.limits).hex(),
        predecessor_state_hex=canonical_json_bytes(prior).hex(),
        preparation_receipt_hex=canonical_json_bytes(preparation).hex(),
        retained_history_sha256=body.retained_history_sha256,
        source_root=preparation["source_root"],
        candidate_root=preparation["candidate_root"],
        source_database_sha256=preparation["source_database_sha256"],
        candidate_database_sha256=preparation["candidate_database_sha256"],
        migration_finalized_block=195,
        service_uid=os.geteuid(),
    )
    values = c.receipt.model_dump(by_alias=True)
    values.update(
        schema="umi-successor-installation-receipt/2",
        evidence_migration=seal,
        operator_consent_sha256=original_consent_digest(consent),
        operator_consent_size_bytes=len(canonical_json_bytes(consent)),
        host_manifest_sha256=target.approved_host_manifest_sha256,
        worker_limits_sha256=digest(limits),
        worker_limits_size_bytes=len(canonical_json_bytes(limits)),
    )
    receipt = activation.SuccessorInstallationReceipt.model_validate(values)
    return SimpleNamespace(
        case=c, consent=consent, limits=limits, receipt=receipt, seal=seal, body=body
    )


@pytest.fixture
def complete_migration(migrated, monkeypatch, tmp_path, policy, replay_limits, package_limits):
    """Native signed history/package and complete fixed-mount loader.

    Inference and OS mount ownership use the existing fixture ports. This does
    not execute a host binary, stop a real validator, or submit a transaction.
    """
    from umi.competition_history_compatibility import transition_target_consent
    from umi.competition_host_artifacts import SignedSuccessorHostArtifact
    from umi.competition_package import (
        competition_release_identity_digest,
        prepare_competition_package,
    )
    from umi.competition_supervisor import successor_operator_consent_sha256

    from . import test_competition_publication as publication
    from .test_competition_host_artifacts import sign as sign_host
    from .test_competition_supervisor import _exact_package_target

    m, c = migrated, migrated.case
    original = activation.load_successor_worker_inputs()
    identity = c.release_identity.model_copy(update={"umi_revision": "43" * 20})
    release = c.release.model_copy(
        update={"umi_git_revision": identity.umi_revision, "replay_release_identity": identity}
    )
    round_for = publication.round_for
    monkeypatch.setattr(
        publication,
        "round_for",
        lambda *a, **k: round_for(*a, **k).model_copy(
            update={"sequence": c.target.round_sequence + 1}
        ),
    )
    scenario = publication._scenario(policy, tmp_path / "replacement-scenario", replay_limits)
    prepared = prepare_competition_package(
        policy=policy,
        cutoff_certificate=scenario.cutoff_certificate,
        settlement_certificate=scenario.settlement_certificate,
        retained_settlement=scenario.settlement,
        roster=scenario.submissions,
        evidence=scenario.evidence,
        replay_limits=replay_limits,
        release_identity=identity,
        destination_root=tmp_path / "replacement-packages",
        limits=package_limits,
    )
    package_path = Path(prepared.package_path)
    target = _exact_package_target(
        SimpleNamespace(path=package_path, prepared=prepared), package_limits, policy
    )
    old_host = SignedSuccessorHostArtifact.model_validate_json(
        (c.anchor / activation.SIGNED_HOST_ARTIFACT_FILENAME).read_bytes()
    )
    new_host = sign_host(old_host.manifest.model_copy(update={"umi_git_revision": "43" * 20}))
    target_consent = transition_target_consent(m.consent).model_copy(
        update={"approved_host_manifest_sha256": new_host.manifest_sha256}
    )
    body = m.body.model_copy(
        update={
            "target_host_manifest_sha256": new_host.manifest_sha256,
            "target_consent_sha256": original_consent_digest(target_consent),
            "target_release_identity_sha256": competition_release_identity_digest(identity),
            "target_oci_manifest_sha256": release.oci_manifest_sha256,
            "target_source_tree_sha256": release.umi_source_tree_sha256,
        }
    )
    consent = SuccessorSupervisorOperatorConsent.model_validate(
        {
            **target_consent.model_dump(by_alias=True),
            "schema": "umi-validator-supervisor-operator-consent/2",
            "historical_consent": c.consent,
            "history_compatibility": sign(body),
        }
    )
    seal = m.seal.model_copy(update={"compatibility_sha256": digest(consent.history_compatibility)})
    receipt = m.receipt.model_copy(
        update={
            "evidence_migration": seal,
            "operator_consent_sha256": successor_operator_consent_sha256(consent),
            "operator_consent_size_bytes": len(canonical_json_bytes(consent)),
            "signed_host_artifact_sha256": digest(new_host),
            "signed_host_artifact_size_bytes": len(canonical_json_bytes(new_host)),
            "host_manifest_sha256": new_host.manifest_sha256,
            "host_umi_git_revision": new_host.manifest.umi_git_revision,
        }
    )
    selected = SimpleNamespace(
        **{
            **vars(c),
            "target": target,
            "release_identity": identity,
            "release": release,
            "consent": consent,
            "signed": original.current_page.head,
        }
    )
    rollover = _weight_rollover(selected)
    signed = rollover.signed
    page = original.current_page.model_copy(
        update={"directives": [*original.current_page.directives, signed], "head": signed}
    )
    execution = rollover.execution.model_copy(
        update={
            "schema_": "umi-successor-worker-execution-config/2",
            "weights": rollover.execution.weights.model_copy(
                update={"evidence_storage": m.limits.weight_evidence_storage}
            ),
        }
    )
    for name, value in (
        (activation.OPERATOR_CONSENT_FILENAME, consent),
        (activation.SIGNED_HOST_ARTIFACT_FILENAME, new_host),
        (activation.WORKER_LIMITS_FILENAME, m.limits),
        (activation.INSTALLATION_RECEIPT_FILENAME, receipt),
    ):
        _replace_control(c.anchor / name, value)
    _install_weight_rollover(
        c, SimpleNamespace(page=page, execution=execution, authorization=rollover.authorization)
    )
    _replace_control(c.current / activation.RELEASE_IDENTITY_FILENAME, identity)
    c.current.chmod(0o755)
    current_package = c.current / activation.PACKAGE_DIRECTORY_NAME
    _restore_writable(current_package)
    shutil.rmtree(current_package)
    shutil.copytree(package_path, current_package)
    c.current.chmod(0o555)
    yield SimpleNamespace(
        original=original, case=c, consent=consent, receipt=receipt, signed=signed, seal=seal
    )
    _restore_writable(package_path)


@pytest.mark.parametrize("migrated", ["weights"], indirect=True)
async def test_complete_migrated_host_loads_old_history_and_new_weight_package(
    complete_migration, weight_case
):
    m = complete_migration
    inputs = activation.load_successor_worker_inputs()
    activation.validate_authenticated_successor_installation(inputs)
    _advance(weight_case, 195)
    weight_case.rpc.values.update(
        {
            ("SubtensorModule", "Uids", (78, inputs.validator_hotkey)): 54,
            ("SubtensorModule", "Keys", (78, 54)): inputs.validator_hotkey,
            ("System", "Account", (inputs.validator_hotkey,)): {"nonce": 4, "providers": 1},
            ("Commitments", "CommitmentOf", (78, inputs.validator_hotkey)): None,
        }
    )
    observation = await weight_case.provider.collect_weights(
        inputs.validator_hotkey, weight_case.recipients
    )
    active = activation.activate_successor_worker(inputs, owned_observation=observation)
    assert active.signed_directive == m.signed
    assert inputs.profile == "competition_weights"
    assert inputs.initial_page == m.original.initial_page
    assert inputs.checkpoint_sha256 == m.original.checkpoint_sha256
    assert inputs.current_page.directives[:-1] == m.original.current_page.directives
    assert activation.selected_weight_state_root(inputs) == Path(m.seal.candidate_root)
    assert (
        activation.retained_execution_limits(inputs, m.original.signed_directive.directive)
        == m.original.worker_execution_limits
    )
    assert inputs.worker_execution_limits.weight_evidence_storage is not None
    assert not hasattr(active, "submitted")


@pytest.mark.parametrize("migrated", ["weights"], indirect=True)
def test_migrated_loader_rejects_replaced_retained_signed_history(complete_migration):
    from umi.competition_weights import sign_competition_weight_authorization

    from .test_competition_supervisor import (
        _signed,
        _signed_authorization_target,
        authority_wallets,
    )

    m = complete_migration
    inputs = activation.load_successor_worker_inputs()
    previous = inputs.current_page.directives[0]
    replacement = _signed(
        previous.directive.model_copy(
            update={"valid_through_block": previous.directive.valid_through_block - 1}
        )
    )
    # Keep the replacement page structurally contiguous and signed. It must
    # fail the retained-history binding, not merely a malformed-page check.
    authorization = sign_competition_weight_authorization(
        inputs.authorization.authorization.model_copy(
            update={"predecessor_directive_sha256": replacement.directive_sha256}
        ),
        authority_wallets()[0],
    )
    head = _signed(
        inputs.signed_directive.directive.model_copy(
            update={
                "previous_directive_sha256": replacement.directive_sha256,
                "chain_authorization": _signed_authorization_target(authorization),
            }
        )
    )
    page = inputs.current_page.model_copy(update={"directives": [replacement, head], "head": head})
    _replace_control(m.case.current / activation.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME, page)
    _replace_control(m.case.current / activation.WEIGHT_AUTHORIZATION_FILENAME, authorization)
    with pytest.raises(
        activation.HostActivationError,
        match="retained signed history differs from migration authorization",
    ):
        activation.load_successor_worker_inputs()


@pytest.mark.parametrize("migrated", ["weights"], indirect=True)
def test_migrated_loader_rejects_new_signed_release_outside_grant(complete_migration):
    from umi.validator_supervisor import ValidatorSupervisorError

    from .test_competition_supervisor import _signed

    m = complete_migration
    inputs = activation.load_successor_worker_inputs()
    directive = inputs.signed_directive.directive
    replacement = _signed(
        directive.model_copy(
            update={
                "release": directive.release.model_copy(update={"oci_manifest_sha256": "8a" * 32})
            }
        )
    )
    page = inputs.current_page.model_copy(
        update={
            "directives": [*inputs.current_page.directives[:-1], replacement],
            "head": replacement,
        }
    )
    _replace_control(m.case.current / activation.CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME, page)
    with pytest.raises(
        ValidatorSupervisorError, match="historical_compatibility_forward_scope_mismatch"
    ):
        activation.load_successor_worker_inputs()


def check(m, receipt=None, consent=None):
    activation.validate_evidence_migration_receipt(
        receipt or m.receipt,
        config=m.case.config,
        consent=consent or m.consent,
        worker_limits_bytes=canonical_json_bytes(m.limits),
    )


def test_migration_preserves_original_root_bytes(migrated):
    check(migrated)
    assert bytes.fromhex(migrated.seal.original_receipt_hex) == canonical_json_bytes(
        migrated.case.receipt
    )
    assert bytes.fromhex(migrated.seal.original_worker_limits_hex) == canonical_json_bytes(
        migrated.case.limits
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("checkpoint_sha256", "a1" * 32),
        ("checkpoint_chain_config_sha256", "a2" * 32),
        ("initial_successor_page_sha256", "a3" * 32),
        ("legacy_installation_sha256", "a4" * 32),
        ("worker_limits_sha256", "a5" * 32),
        ("host_manifest_sha256", "a6" * 32),
    ],
)
def test_rewritten_installation_history_rejected(migrated, field, value):
    with pytest.raises(ValueError):
        check(migrated, receipt=migrated.receipt.model_copy(update={field: value}))


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_database_sha256", "a1" * 32),
        ("candidate_database_sha256", "a2" * 32),
        ("retained_history_sha256", "a3" * 32),
        ("compatibility_sha256", "a4" * 32),
        ("migration_finalized_block", 251),
        ("predecessor_state_hex", b"{}".hex()),
    ],
)
def test_changed_migration_binding_rejected(migrated, field, value):
    seal = migrated.seal.model_copy(update={field: value})
    with pytest.raises(ValueError):
        check(migrated, receipt=migrated.receipt.model_copy(update={"evidence_migration": seal}))


def test_consent_without_root_migration_is_rejected(migrated):
    with pytest.raises(ValueError):
        check(migrated, receipt=migrated.case.receipt)


@pytest.fixture
def transaction(migrated, tmp_path, monkeypatch):
    # These tests exercise real canonical records/quorum checks/control fsync and
    # interrupted transaction recovery. Root ownership and Linux's indivisible
    # renameat2 are represented by an OS shim; Linux power-loss is not claimed.
    parent = tmp_path / "switch"
    parent.mkdir()
    live, prepared = parent / "live", parent / "prepared"
    for root, receipt, consent, worker_limits in (
        (live, migrated.case.receipt, migrated.case.consent, migrated.case.limits),
        (prepared, migrated.receipt, migrated.consent, migrated.limits),
    ):
        (root / "anchor").mkdir(parents=True)
        for name, value in (
            ("installation-receipt.json", receipt),
            ("operator-consent.json", consent),
            ("worker-limits.json", worker_limits),
        ):
            path = root / "anchor" / name
            path.write_bytes(canonical_json_bytes(value))
            path.chmod(0o444)
    journal = parent / "transaction"
    journal.mkdir(mode=0o700)
    plan = switch.EvidenceActivationPlan(
        live,
        prepared,
        journal,
        digest(migrated.case.receipt),
        digest(migrated.receipt),
        digest(migrated.consent.history_compatibility),
    )
    monkeypatch.setattr(switch, "_root_linux", lambda: None)
    monkeypatch.setattr(switch, "_validate_lease", lambda lease, plan, config: lease.recheck())

    def private(path):
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY)

    monkeypatch.setattr(switch, "_private_transaction_root", private)
    monkeypatch.setattr(switch, "_root_control", lambda path: path.read_bytes())
    exchanges = []

    def exchange(fd, left, right):
        exchanges.append((left, right))
        os.rename(left, "exchange-temporary", src_dir_fd=fd, dst_dir_fd=fd)
        os.rename(right, left, src_dir_fd=fd, dst_dir_fd=fd)
        os.rename("exchange-temporary", right, src_dir_fd=fd, dst_dir_fd=fd)

    monkeypatch.setattr(switch, "_exchange", exchange)

    class Lease:
        calls = 0
        failure = None

        def recheck(self):
            self.calls += 1
            if self.calls == self.failure:
                raise RuntimeError("stopped lease lost")

    result = SimpleNamespace(m=migrated, plan=plan, lease=Lease(), exchanges=exchanges)
    yield result
    _restore_writable(parent)


def publish(t):
    return switch.publish_stopped_evidence_activation(t.plan, config=t.m.case.config, lease=t.lease)


@pytest.mark.parametrize("boundary", [1, 2, 3, 4])
def test_stopped_lease_loss_never_rolls_back_or_repeats_exchange(transaction, boundary):
    t = transaction
    t.lease.failure = boundary
    with pytest.raises(RuntimeError, match="lease lost"):
        publish(t)
    t.lease.failure = None
    first = publish(t)
    assert publish(t) == first
    assert len(t.exchanges) == 1
    assert switch._receipt(t.plan.live_source)[1] == t.plan.candidate_receipt_sha256
    assert switch._receipt(t.plan.prepared_source)[1] == t.plan.original_receipt_sha256


@pytest.mark.parametrize("name", ["activation-plan.json", "activation-complete.json"])
def test_interrupted_control_fsync_resumes_same_plan(transaction, monkeypatch, name):
    t = transaction
    writer = switch._write_control

    def interrupt(fd, target, raw):
        writer(fd, target, raw)
        if target == name:
            raise RuntimeError("power loss after control fsync")

    monkeypatch.setattr(switch, "_write_control", interrupt)
    with pytest.raises(RuntimeError):
        publish(t)
    monkeypatch.setattr(switch, "_write_control", writer)
    publish(t)
    assert len(t.exchanges) == 1


def test_changed_resume_plan_refused(transaction):
    t = transaction
    publish(t)
    from dataclasses import replace

    changed = replace(t.plan, candidate_receipt_sha256="ff" * 32)
    with pytest.raises(ValueError, match="control changed"):
        switch.publish_stopped_evidence_activation(changed, config=t.m.case.config, lease=t.lease)
    assert len(t.exchanges) == 1
