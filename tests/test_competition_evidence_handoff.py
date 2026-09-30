"""Combined durable exchange/publication/start with fixture OS and capabilities.

Receipts and grants, immutable records, file replacements, lock ownership and
interrupted resume use their native implementations. Linux systemd, candidate
archive sealing and live proof capabilities are fixture ports in this suite.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager, contextmanager
from dataclasses import replace

import pytest

from umi import competition_evidence_activation as activation
from umi import competition_evidence_handoff as handoff
from umi import competition_evidence_resume as resume
from umi import competition_evidence_service as service
from umi.competition_upgrade import _Reader
from umi.protocol import canonical_json_bytes

from .test_competition_evidence_activation import (
    activation_case,
    chain,
    chain_config,
    explicit,
    limits,
    migrated,
    package_case,
    package_limits,
    policy,
    release_identity,
    replay_limits,
    successor_release,
    transaction,
    trusted_ports,
    weight_case,
    worker_capacity,
)
from .test_competition_evidence_resume import ready, selected

__all__ = [
    "activation_case",
    "chain",
    "chain_config",
    "explicit",
    "limits",
    "migrated",
    "package_case",
    "package_limits",
    "policy",
    "ready",
    "release_identity",
    "replay_limits",
    "selected",
    "successor_release",
    "transaction",
    "trusted_ports",
    "weight_case",
    "worker_capacity",
]


@pytest.fixture
def combined(transaction, ready, monkeypatch):
    t, c = transaction, ready
    old_root = c.root
    c.root, c.plan = t.plan.transaction_root, t.plan
    c.anchor.source_root = c.plan.live_source
    c.anchor.receipt_sha256 = c.plan.candidate_receipt_sha256
    c.anchor.receipt.evidence_migration.compatibility_sha256 = c.plan.compatibility_sha256
    c.runtime.host_manifest_sha256 = t.m.receipt.host_manifest_sha256
    c.anchor.receipt.host_manifest_sha256 = c.runtime.host_manifest_sha256
    c.conditions[0][3] = str(c.root / "HOLD")
    (c.root / "HOLD").write_bytes(
        service.evidence_service_hold(c.unit, c.runtime.host_manifest_sha256)
    )
    (c.root / "HOLD").chmod(0o444)
    for path, body in (
        (c.runtime.drop_in_path, c.old),
        (c.runtime.cleanup_unit_path, c.old_cleanup),
    ):
        path.chmod(0o600)
        path.write_bytes(body)
        path.chmod(0o444)
    config_path = c.args["config_path"]
    config_path.write_bytes(canonical_json_bytes(t.m.case.config))
    config_path.chmod(0o600)
    c.eligible = object()
    c.lease_active = False
    c.mutex_active = False
    c.seal_calls = 0
    c.verify_calls = 0
    c.native_boundaries = t.exchanges
    c.inputs = handoff.PreparedEvidenceHandoff(
        plan=c.plan,
        config_path=config_path,
        unit_name=c.unit,
        candidate_receipt=t.m.receipt,
        consent=t.m.consent,
        worker_limits_bytes=canonical_json_bytes(t.m.limits),
        verified_host_tree=c.tree,
        signed_host=None,
        observer_config=None,
    )

    def recheck():
        assert c.lease_active and c.mutex_active

    def scope(plan, config):
        recheck()
        assert plan == c.plan

    monkeypatch.setattr(c.lease, "recheck", recheck, raising=False)
    monkeypatch.setattr(c.lease, "validate_scope", scope)

    @contextmanager
    def mutex(unit):
        assert unit == c.unit and not c.mutex_active
        c.mutex_active = True
        try:
            yield
        finally:
            c.mutex_active = False

    @asynccontextmanager
    async def stopped(plan, **arguments):
        assert c.mutex_active and plan == c.plan
        c.verify_calls += 1
        if arguments["eligible_replacement"] is not c.eligible:
            raise ValueError("replacement proof unavailable")
        c.lease_active = True
        try:
            yield c.lease
        finally:
            c.lease_active = False

    def seal(plan, *, config, receipt, lease):
        # The fixture already supplies the sealed archive. Keep actual canonical
        # signed-receipt validation and preserve exactly those candidate bytes.
        c.seal_calls += 1
        lease.validate_scope(plan, config)
        assert activation._receipt(plan.prepared_source)[1] == plan.candidate_receipt_sha256
        activation.validate_evidence_migration_receipt(
            receipt,
            config=config,
            consent=t.m.consent,
            worker_limits_bytes=canonical_json_bytes(t.m.limits),
        )

    command = resume._service_command

    def service_command(*args):
        assert c.mutex_active and not c.lease_active
        return command(*args)

    monkeypatch.setattr(handoff, "_require_root_linux", lambda: None)
    monkeypatch.setattr(handoff, "ensure_coordinator_host_view", lambda **_: None)
    monkeypatch.setattr(handoff, "exclusive_upgrade_operation", mutex)
    monkeypatch.setattr(handoff, "_Reader", lambda _: _Reader(os.getuid()))
    monkeypatch.setattr(handoff, "successor_activation_source_root", lambda _: c.plan.live_source)
    monkeypatch.setattr(handoff, "hold_stopped_evidence_migration", stopped)
    monkeypatch.setattr(handoff, "seal_prepared_evidence_installation", seal)
    monkeypatch.setattr(resume, "_service_command", service_command)
    # Original fixtures expose one fixed guard path. Its content/condition and
    # the root hold itself are still checked by native publication and startup.
    monkeypatch.setattr(handoff, "_held", service._held)
    # service._receipt is the fixture's materialized-anchor OS port; activation
    # uses actual signed receipts at the physically exchanged directory paths.
    monkeypatch.setattr(
        service, "_receipt", lambda _: (c.anchor.receipt, c.plan.candidate_receipt_sha256)
    )
    assert old_root != c.root
    return c


async def unused():
    raise AssertionError("fixture proof adapter must not be invoked")


def run(c, *, eligible=True):
    return handoff.finish_stopped_evidence_handoff(
        c.inputs,
        eligible_replacement=c.eligible if eligible else None,
        observe_after_audit=unused,
        verify_worker_stopped=unused,
    )


def test_complete_handoff_preserves_original_anchor_and_starts_after_lease_closes(combined):
    c = combined
    result = run(c)
    assert result["service_started"] and not result["chain_submission_authorized"]
    assert activation._receipt(c.plan.live_source)[1] == c.plan.candidate_receipt_sha256
    assert activation._receipt(c.plan.prepared_source)[1] == c.plan.original_receipt_sha256
    assert len(c.native_boundaries) == 1 and c.seal_calls == 1 and c.verify_calls == 1
    assert (c.root / "original-supervisor.conf").read_bytes() == c.old
    assert (c.root / "original-cleanup.service").read_bytes() == c.old_cleanup
    assert run(c, eligible=False) == result
    assert c.verify_calls == 1 and c.calls.count(("start", c.unit)) == 1


@pytest.mark.parametrize(
    "boundary", ["exchange", "runtime_file", "publication", "hold_release", "started"]
)
def test_restart_recovers_same_handoff_without_exchanging_back_or_starting_twice(
    combined, monkeypatch, boundary
):
    c = combined
    exchange, replace_file, write = (
        activation._exchange,
        service._replace_control,
        service._write_control,
    )
    move, start_write = resume._move_hold, resume._write_control

    def killed_exchange(*args):
        exchange(*args)
        if boundary == "exchange":
            raise RuntimeError("controller interrupted")

    def killed_replace(path, **kwargs):
        replace_file(path, **kwargs)
        if boundary == "runtime_file":
            raise RuntimeError("controller interrupted")

    def killed_write(fd, name, raw):
        write(fd, name, raw)
        if boundary == "publication" and name == "service-publication.json":
            raise RuntimeError("controller interrupted")

    def killed_move(selection, *, release):
        move(selection, release=release)
        if boundary == "hold_release" and release:
            raise RuntimeError("controller interrupted")

    def killed_start_write(fd, name, raw):
        start_write(fd, name, raw)
        if boundary == "started" and name == "service-start-complete.json":
            raise RuntimeError("controller interrupted")

    with monkeypatch.context() as fault:
        fault.setattr(activation, "_exchange", killed_exchange)
        fault.setattr(service, "_replace_control", killed_replace)
        fault.setattr(service, "_write_control", killed_write)
        fault.setattr(resume, "_move_hold", killed_move)
        fault.setattr(resume, "_write_control", killed_start_write)
        with pytest.raises(RuntimeError, match="controller interrupted"):
            run(c)
    result = run(c, eligible=boundary in {"exchange", "runtime_file"})
    assert result["service_started"]
    assert c.calls.count(("start", c.unit)) == 1 and len(c.native_boundaries) == 1
    assert c.seal_calls == 1  # Never attempt to seal the retained original after exchange.


def test_missing_fresh_replacement_cannot_publish_or_release_hold(combined):
    c = combined
    with pytest.raises(ValueError, match="replacement proof unavailable"):
        run(c, eligible=False)
    assert not c.native_boundaries and c.seal_calls == 0
    assert (c.root / "HOLD").is_file() and not (c.root / "service-publication.json").exists()


@pytest.mark.parametrize(
    "field", ["live_source", "original_receipt_sha256", "compatibility_sha256"]
)
def test_wrong_installation_or_predecessor_is_rejected_before_sealing(combined, field):
    c = combined
    value = c.plan.live_source.with_name("unrelated") if field == "live_source" else "ff" * 32
    c.inputs = replace(c.inputs, plan=replace(c.plan, **{field: value}))
    with pytest.raises(ValueError, match="installed source or predecessor"):
        run(c)
    assert c.seal_calls == 0 and not c.native_boundaries
    assert (c.root / "HOLD").is_file()


def test_completed_publication_still_rejects_different_plan(combined):
    c = combined
    run(c)
    c.inputs = replace(c.inputs, plan=replace(c.plan, compatibility_sha256="ff" * 32))
    with pytest.raises(ValueError, match="another activation plan"):
        run(c, eligible=False)
    assert c.calls.count(("start", c.unit)) == 1


def test_tampered_publication_cannot_be_used_to_skip_stopped_verification(combined):
    c = combined
    (c.root / "service-publication.json").write_bytes(b"{}")
    (c.root / "service-publication.json").chmod(0o600)
    with pytest.raises((ValueError, KeyError, FileNotFoundError)):
        run(c, eligible=False)
    assert (c.root / "HOLD").is_file() and not c.native_boundaries
