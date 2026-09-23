from __future__ import annotations

import hashlib
import os
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
    _restore_writable,
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


@pytest.fixture
def migrated(activation_case, tmp_path):
    c = activation_case
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
            [item.model_dump(mode="json", by_alias=True) for item in c.initial_page.directives]
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
