from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_recovery as recovery
from umi.bootstrap_direct_weights import DirectBootstrapSubmissionJournal
from umi.bootstrap_weight_operator import BootstrapExtrinsicReference
from umi.encoding import account_id32
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor_worker import (
    SupervisorBootstrapAuthorizationClaim,
    SupervisorWorkerJournal,
)

from .test_bootstrap_direct_weights import NOW, _operational, _preflight
from .test_simple_bootstrap_validator import (
    BLOCK as SIMPLE_BLOCK,
)
from .test_simple_bootstrap_validator import (
    _journal,
    _production_manifest,
    _ss58,
    _unsigned_production_lease,
)
from .test_validator_supervisor_worker import _terminal_artifacts


def _write(path: Path, value) -> bytes:
    payload = value if isinstance(value, bytes) else canonical_json_bytes(value)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o600)
    return payload


@pytest.fixture
def limits():
    return recovery.RecoveryLimits(
        schema="umi-legacy-bootstrap-recovery-limits/1",
        maximum_files=128,
        maximum_directories=32,
        maximum_depth=8,
        maximum_file_bytes=4 * 1024**2,
        maximum_total_bytes=32 * 1024**2,
        maximum_checkpoint_bytes=1024**2,
        maximum_checkpoints=8,
    )


@pytest.fixture
def explicit(tmp_path, limits):
    signed, auth, owner, participants, preflight = _preflight()
    drain = _operational(signed, preflight)
    material, receipt = _terminal_artifacts(signed, auth, owner, participants)
    root = tmp_path / "worker"
    root.mkdir(mode=0o700)
    supervisor = tmp_path / "supervisor"
    supervisor.mkdir(mode=0o700)
    archives = tmp_path / "archives"
    archives.mkdir(mode=0o700)
    directive = "91" * 32
    transaction = root / "bootstrap-transactions" / directive
    transaction.mkdir(mode=0o700, parents=True)
    transaction.parent.chmod(0o700)
    global_root = root / "bootstrap-authorizations"
    global_root.mkdir(mode=0o700)
    inner_root = global_root / "operator-state"
    inner_root.mkdir(mode=0o700)
    manifest_bytes = _write(transaction / "signed-manifest.json", signed)
    authorization_bytes = _write(transaction / "direct-transition-authorization.json", auth)
    drain_bytes = _write(transaction / "drain-checkpoint.json", drain)
    _write(transaction / "worker.lock", b"")
    _write(transaction / "call-material.json", material)
    receipt_bytes = _write(transaction / "submission-receipt.json", receipt)
    journal = SupervisorWorkerJournal(
        schema="umi-validator-supervisor-worker-journal/1",
        state_schema_version=1,
        mode="bootstrap_service_weights",
        directive_sha256=directive,
        policy_sha256=signed.manifest.policy_sha256,
        release_manifest_sha256="71" * 32,
        sequence=2,
        valid_from_block=125,
        valid_through_block=155,
        validator_hotkey=auth.validator_hotkey,
        manifest_input_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        transition_authorization_input_sha256=hashlib.sha256(authorization_bytes).hexdigest(),
        drain_checkpoint_input_sha256=hashlib.sha256(drain_bytes).hexdigest(),
        phase="completed",
        intent_finalized_block=125,
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        call_material_sha256=receipt.call_material_sha256,
        reason_code=None,
    )
    _write(transaction / "journal.json", journal)
    claim = SupervisorBootstrapAuthorizationClaim(
        schema="umi-validator-supervisor-authorization-claim/1",
        submission_id=auth.submission_id,
        transition_authorization_sha256=journal.transition_authorization_input_sha256,
        manifest_sha256=signed.manifest_sha256,
        validator_hotkey=auth.validator_hotkey,
        directive_sha256=directive,
        sequence=2,
        intent_finalized_block=125,
        intent_finalized_block_hash="0x" + "12" * 32,
    )
    claim_path = global_root / f"claim-{auth.submission_id}.json"
    _write(claim_path, claim)
    inner = DirectBootstrapSubmissionJournal(
        schema="umi-bootstrap-direct-submission-journal/2",
        transition_profile="direct_full_row/2",
        submission_id=auth.submission_id,
        phase="applied",
        manifest_sha256=signed.manifest_sha256,
        transition_authorization_sha256=journal.transition_authorization_input_sha256,
        validator_hotkey=auth.validator_hotkey,
        anchor=receipt.anchor,
        call_material_sha256=receipt.call_material_sha256,
        weight_call=receipt.weight_call,
        receipt_sha256=journal.receipt_sha256,
        updated_at=NOW,
    )
    inner_path = inner_root / (
        f"direct-{journal.transition_authorization_input_sha256}-"
        f"{account_id32(auth.validator_hotkey).hex()}.json"
    )
    _write(inner_path, inner)
    kwargs = dict(
        expected_hotkey=auth.validator_hotkey,
        service_uid=os.getuid(),
        accepted_sequence=2,
        accepted_directive_sha256=directive,
        accepted_at_finalized_block=125,
        config_sha256="61" * 32,
        installation_sha256="51" * 32,
        limits=limits,
    )
    stopped = SimpleNamespace(
        worker_state_root=root,
        state_root=supervisor,
        validator_hotkey=auth.validator_hotkey,
        service_uid=os.getuid(),
        accepted_sequence=2,
        accepted_directive_sha256=directive,
        accepted_at_finalized_block=125,
        config_sha256="61" * 32,
        installation_sha256="51" * 32,
        expected_manifest_sha256=signed.manifest_sha256,
        live=True,
    )
    evidence = canonical_json_bytes({"schema": "test-owned-chain-observation", "block": 180})
    observation = SimpleNamespace(
        validator_hotkey=auth.validator_hotkey,
        validator_uid=auth.validator_uid,
        validator_row=tuple(tuple(row) for row in material.expected_applied_row),
        validator_last_update=130,
        manifest_anchor_sha256=signed.manifest_sha256,
        manifest_anchor_block=126,
        block=180,
        block_hash="0x" + "18" * 32,
        genesis_hash="0x" + "19" * 32,
        chain_config_sha256="29" * 32,
        evidence=evidence,
        evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        commit_reveal_enabled=False,
        live=True,
    )
    item = SimpleNamespace(**locals())
    yield item
    # Let pytest remove only the synthetic readonly archives made by this test.
    for path in archives.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o700 if path.is_dir() else 0o600)


@pytest.fixture
def trusted_ports(explicit, monkeypatch):
    """In-process unit ports only; production entrypoints have no such switches."""
    item = explicit

    def stopped(value):
        if value is not item.stopped or not value.live:
            raise ValueError("invalid test stopped lease")

    def observation(value, host):
        stopped(host)
        if value is not item.observation or not value.live:
            raise ValueError("invalid test owned observation")

    monkeypatch.setattr(recovery, "_check_stopped", stopped)
    monkeypatch.setattr(recovery, "_check_owned", observation)
    return item


def _prepare(item, **kwargs):
    return recovery.prepare_recovery_checkpoint(
        item.stopped,
        item.observation,
        destination_root=item.archives,
        limits=item.limits,
        **kwargs,
    )


def _verify(item, prepared):
    return recovery.verify_recovery_checkpoint(
        Path(prepared.checkpoint_path),
        expected_checkpoint_sha256=prepared.checkpoint_sha256,
        stopped=item.stopped,
        observation=item.observation,
        limits=item.limits,
    )


def test_terminal_explicit_state_replays_without_mutation_or_live_authorization(explicit):
    item = explicit
    before = {path: path.read_bytes() for path in item.root.rglob("*") if path.is_file()}
    with recovery.snapshot_legacy_bootstrap(item.root, **item.kwargs) as snapshot:
        assert snapshot.manifest.holds == []
        assert [effect.classification for effect in snapshot.manifest.effects] == [
            "retained_weight_receipt"
        ]
        assert snapshot.manifest.chain_submission_authorized is False
        assert snapshot.manifest.snapshot_does_not_prove_service_stopped is True
        assert len(snapshot._files) == 9
    assert before == {path: path.read_bytes() for path in before}


def test_stopped_checkpoint_roundtrip_restart_and_no_wallet(trusted_ports, monkeypatch):
    item = trusted_ports
    import bittensor

    monkeypatch.setattr(bittensor, "Wallet", lambda **_: pytest.fail("recovery opened a wallet"))
    prepared = _prepare(item)
    assert prepared.prior_effects_reconciled and not prepared.holds
    assert not prepared.chain_submission_authorized
    capability = _verify(item, prepared)
    recovery.validate_checkpoint_for_successor(
        capability,
        validator_hotkey=item.auth.validator_hotkey,
        predecessor_directive_sha256=item.directive,
        minimum_finalized_block=180,
    )
    body = json.loads((Path(prepared.checkpoint_path) / "checkpoint.json").read_bytes())
    assert body["pending_queue_absence_proven"] is False
    assert body["historical_authorizations_reactivated"] is False
    assert body["reconciled_effects"][0]["classification"] == "proven_current_weight"
    assert _prepare(item) == prepared
    assert _verify(item, prepared).checkpoint_sha256 == capability.checkpoint_sha256


@pytest.mark.parametrize("phase", ["prepared", "effect_intent", "ambiguous"])
def test_global_claim_survives_outer_phase_and_incomplete_inner_hold(explicit, phase):
    item = explicit
    journal = item.journal.model_copy(
        update={
            "phase": phase,
            "receipt_sha256": None,
            "call_material_sha256": None,
            "intent_finalized_block": None if phase == "prepared" else 125,
            "reason_code": "interrupted" if phase == "ambiguous" else None,
        }
    )
    _write(item.transaction / "journal.json", journal)
    item.inner_path.unlink()
    with recovery.snapshot_legacy_bootstrap(item.root, **item.kwargs) as snapshot:
        assert snapshot.manifest.holds
        assert snapshot.manifest.effects[0].classification == "unresolved"


def test_effect_intent_with_all_exact_terminal_artifacts_recovers_without_submission(explicit):
    item = explicit
    _write(
        item.transaction / "journal.json",
        item.journal.model_copy(
            update={
                "phase": "effect_intent",
                "receipt_sha256": None,
                "call_material_sha256": None,
            }
        ),
    )
    with recovery.snapshot_legacy_bootstrap(item.root, **item.kwargs) as snapshot:
        assert snapshot.manifest.holds == []
        assert snapshot.manifest.effects[0].classification == "retained_weight_receipt"


def test_orphan_global_claim_is_retained_and_holds(explicit):
    item = explicit
    claim = item.claim.model_copy(update={"submission_id": "82" * 32})
    path = item.global_root / f"claim-{claim.submission_id}.json"
    _write(path, claim)
    with recovery.snapshot_legacy_bootstrap(item.root, **item.kwargs) as snapshot:
        assert "orphan_global_authorization_claim" in snapshot.manifest.holds
        assert snapshot._files[path.relative_to(item.root).as_posix()] == canonical_json_bytes(
            claim
        )


def test_prepared_without_claim_is_distinct_from_uncertain_intent(explicit):
    item = explicit
    item.claim_path.unlink()
    item.inner_path.unlink()
    (item.transaction / "call-material.json").unlink()
    (item.transaction / "submission-receipt.json").unlink()
    _write(
        item.transaction / "journal.json",
        item.journal.model_copy(
            update={
                "phase": "prepared",
                "intent_finalized_block": None,
                "receipt_sha256": None,
                "call_material_sha256": None,
            }
        ),
    )
    with recovery.snapshot_legacy_bootstrap(item.root, **item.kwargs) as snapshot:
        assert snapshot.manifest.holds == []
        assert snapshot.manifest.effects[0].classification == "prepared_without_effect_intent"


@pytest.mark.parametrize(
    "mutation", ["journal_hotkey", "claim_directive", "sequence", "input_bytes", "receipt", "inner"]
)
def test_inconsistent_history_fails_before_checkpoint(explicit, mutation):
    item = explicit
    if mutation == "journal_hotkey":
        value = item.journal.model_copy(update={"validator_hotkey": _ss58("other")})
        _write(item.transaction / "journal.json", value)
    elif mutation == "claim_directive":
        _write(item.claim_path, item.claim.model_copy(update={"directive_sha256": "32" * 32}))
    elif mutation == "sequence":
        _write(item.transaction / "journal.json", item.journal.model_copy(update={"sequence": 3}))
    elif mutation == "input_bytes":
        _write(item.transaction / "signed-manifest.json", canonical_json_bytes(item.signed) + b"\n")
    elif mutation == "receipt":
        _write(
            item.transaction / "submission-receipt.json",
            item.receipt.model_copy(update={"observed_last_update": 129}),
        )
    else:
        _write(item.inner_path, item.inner.model_copy(update={"receipt_sha256": "92" * 32}))
    with (
        pytest.raises((ValueError, RuntimeError)),
        recovery.snapshot_legacy_bootstrap(item.root, **item.kwargs),
    ):
        pass
    assert list(item.archives.iterdir()) == []


@pytest.mark.parametrize(
    "phase", ["outcome_unknown", "not_applied", "anchor_not_applied", "recovered_applied"]
)
def test_common_timeout_does_not_prove_absence_or_mortality(explicit, phase):
    item = explicit
    common = _journal(
        item.auth.validator_hotkey,
        phase=phase,
        observation_block=None if phase == "outcome_unknown" else 9_100_000,
        manifest_anchor_block=None if phase == "anchor_not_applied" else 9_000_000,
    )
    _write(item.root / "journal.json", common)
    _write(item.root / "service.lock", b"")
    with recovery.snapshot_legacy_bootstrap(
        item.root, **item.kwargs, historical_manifests=(_production_manifest(),)
    ) as snapshot:
        effect = next(
            effect for effect in snapshot.manifest.effects if effect.path == "journal.json"
        )
        assert effect.classification == "unresolved"
        assert "common_historical_context_missing" in snapshot.manifest.holds


@pytest.mark.parametrize(
    "mutation", ["symlink", "parent_symlink", "hardlink", "mode", "owner", "fifo"]
)
def test_unsafe_legacy_files_are_never_followed(explicit, mutation, monkeypatch):
    item = explicit
    source = item.transaction / "journal.json"
    if mutation == "symlink":
        source.rename(source.with_name("saved.json"))
        source.symlink_to(source.with_name("saved.json"))
    elif mutation == "parent_symlink":
        moved = item.root.parent / "moved"
        item.root.rename(moved)
        item.root.symlink_to(moved, target_is_directory=True)
    elif mutation == "hardlink":
        os.link(source, source.with_name("linked.json"))
    elif mutation == "mode":
        source.chmod(0o644)
    elif mutation == "owner":
        item.kwargs["service_uid"] = os.getuid() + 1
    else:
        os.mkfifo(item.root / "pipe", mode=0o600)
    with (
        pytest.raises((ValueError, OSError)),
        recovery.snapshot_legacy_bootstrap(item.root, **item.kwargs),
    ):
        pass


@pytest.mark.parametrize(
    "limit,value",
    [
        ("maximum_files", 1),
        ("maximum_directories", 1),
        ("maximum_depth", 1),
        ("maximum_file_bytes", 100),
        ("maximum_total_bytes", 100),
    ],
)
def test_source_bounds_are_enforced_before_retention(explicit, limit, value):
    item = explicit
    changes = {limit: value}
    if limit == "maximum_total_bytes":
        changes["maximum_file_bytes"] = value
    item.kwargs["limits"] = item.limits.model_copy(update=changes)
    with pytest.raises(ValueError), recovery.snapshot_legacy_bootstrap(item.root, **item.kwargs):
        pass


def test_running_legacy_lock_cannot_be_snapshotted(explicit):
    item = explicit
    descriptor = os.open(item.transaction / "worker.lock", os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (
            pytest.raises(BlockingIOError),
            recovery.snapshot_legacy_bootstrap(item.root, **item.kwargs),
        ):
            pass
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("change", ["file", "directory", "inode"])
def test_snapshot_context_detects_changes_before_exit(explicit, change):
    item = explicit
    with (
        pytest.raises(ValueError, match="changed"),
        recovery.snapshot_legacy_bootstrap(item.root, **item.kwargs),
    ):
        if change == "file":
            _write(item.transaction / "journal.json", item.journal)
        elif change == "directory":
            _write(item.root / "new.json", {})
        else:
            original = item.transaction / "journal.json"
            original.rename(item.transaction / "old.json")
            _write(original, item.journal)


@pytest.mark.parametrize(
    "mutation", ["row", "anchor", "last_update", "uid", "commit_reveal", "before_weight"]
)
def test_fresh_chain_mismatch_retains_held_checkpoint(trusted_ports, mutation):
    item = trusted_ports
    if mutation == "row":
        item.observation.validator_row = ()
    elif mutation == "anchor":
        item.observation.manifest_anchor_sha256 = None
    elif mutation == "last_update":
        item.observation.validator_last_update = 100
    elif mutation == "uid":
        item.observation.validator_uid += 1
    elif mutation == "before_weight":
        item.observation.validator_last_update = 129
    else:
        item.observation.commit_reveal_enabled = True
    prepared = _prepare(item)
    assert prepared.holds and not prepared.prior_effects_reconciled
    with pytest.raises(ValueError, match="unresolved"):
        _verify(item, prepared)


@pytest.mark.parametrize(
    "mutation", ["archive_object", "archive_mode", "source", "stopped", "observation", "capability"]
)
def test_checkpoint_cannot_authorize_after_state_or_lease_change(trusted_ports, mutation):
    item = trusted_ports
    prepared = _prepare(item)
    capability = _verify(item, prepared)
    if mutation == "archive_object":
        path = next((Path(prepared.checkpoint_path) / "objects").iterdir())
        path.chmod(0o600)
        path.write_bytes(b"tampered")
        with pytest.raises(ValueError):
            _verify(item, prepared)
        return
    if mutation == "archive_mode":
        Path(prepared.checkpoint_path).chmod(0o700)
        with pytest.raises(ValueError):
            _verify(item, prepared)
        return
    if mutation == "source":
        _write(item.transaction / "journal.json", item.journal)
    elif mutation == "stopped":
        item.stopped.live = False
    elif mutation == "observation":
        item.observation.live = False
    else:
        capability = replace(capability, accepted_sequence=99)
    with pytest.raises(ValueError):
        recovery.validate_checkpoint_for_successor(
            capability,
            validator_hotkey=item.auth.validator_hotkey,
            predecessor_directive_sha256=item.directive,
            minimum_finalized_block=180,
        )


def test_checkpoint_capacity_is_durable_and_exact_retry_is_allowed(trusted_ports):
    item = trusted_ports
    item.limits = item.limits.model_copy(update={"maximum_checkpoints": 1})
    first = _prepare(item)
    assert _prepare(item) == first
    item.observation.block += 1
    with pytest.raises(ValueError, match="capacity"):
        _prepare(item)
    assert sorted(path.name for path in item.archives.iterdir()) == [
        first.checkpoint_sha256,
        "recovery.lock",
    ]


def test_interrupted_archive_stays_inert_and_is_never_replaced(trusted_ports, monkeypatch):
    item = trusted_ports
    original = recovery._write_new_at
    calls = 0

    def interrupted(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated power loss")
        return original(*args)

    monkeypatch.setattr(recovery, "_write_new_at", interrupted)
    with pytest.raises(OSError, match="power loss"):
        _prepare(item)
    directory = next(path for path in item.archives.iterdir() if path.is_dir())
    before = {str(path): path.read_bytes() for path in directory.rglob("*") if path.is_file()}
    assert directory.stat().st_mode & 0o777 == 0o700
    monkeypatch.setattr(recovery, "_write_new_at", original)
    with pytest.raises(ValueError, match=r"incomplete|mutable"):
        _prepare(item)
    assert before == {
        str(path): path.read_bytes() for path in directory.rglob("*") if path.is_file()
    }


def test_checkpoint_archive_lock_prevents_competing_preparation(trusted_ports):
    item = trusted_ports
    lock = item.archives / "recovery.lock"
    _write(lock, b"")
    descriptor = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            _prepare(item)
        assert list(item.archives.iterdir()) == [lock]
    finally:
        os.close(descriptor)


def test_recovery_uses_real_stopped_host_lease_and_rejects_it_after_release(explicit, monkeypatch):
    from umi import competition_host_upgrade as host

    from .test_competition_upgrade import installation, write
    from .test_validator_supervisor_adapters import _bootstrap_bundle

    item = explicit
    inputs = _bootstrap_bundle().model_copy(
        update={
            "signed_manifest": item.signed,
            "transition_authorization": item.auth,
            "drain_checkpoint": item.drain,
        }
    )
    installed = installation(
        item.tmp_path / "installed",
        inputs,
        "linux/amd64",
        hotkey=item.auth.validator_hotkey,
    )
    write(installed.root / "state" / "supervisor-process.lock", b'{"old":"identity"}', 0o600)
    # Exercise the concrete stopped capability. Only the platform calls are test
    # ports; this test does not assert a real Linux cgroup or GRANDPA rehearsal.
    monkeypatch.setattr(host, "_require_root_linux", lambda: None)
    monkeypatch.setattr(host, "_root_file", lambda _: None)
    monkeypatch.setattr(
        host, "_check_unit", lambda *args: {"FragmentPath": str(installed.config_path)}
    )
    monkeypatch.setattr(
        recovery,
        "_check_owned",
        lambda value, stopped: (
            None
            if value is item.observation and value.validator_hotkey == stopped.validator_hotkey
            else pytest.fail("wrong test observation binding")
        ),
    )
    destination = Path(installed.config.worker_state_root)
    shutil.copytree(item.root, destination, dirs_exist_ok=True)
    old_transaction = destination / "bootstrap-transactions" / item.directive
    directive = installed.signed.directive_sha256
    transaction = old_transaction.with_name(directive)
    old_transaction.rename(transaction)
    _write(
        transaction / "journal.json",
        item.journal.model_copy(
            update={
                "directive_sha256": directive,
                "sequence": 1,
                "release_manifest_sha256": (
                    installed.signed.directive.release.release_manifest_sha256
                ),
            }
        ),
    )
    _write(
        destination / item.claim_path.relative_to(item.root),
        item.claim.model_copy(
            update={
                "directive_sha256": directive,
                "sequence": 1,
            }
        ),
    )
    options = dict(
        config_path=installed.config_path,
        accepted_directive_bytes=canonical_json_bytes(installed.signed),
        expected_hotkey=item.auth.validator_hotkey,
        service_uid=os.getuid(),
    )
    with host.hold_stopped_supervisor(**options) as stopped:
        item.stopped = stopped
        prepared = _prepare(item)
        capability = _verify(item, prepared)
        recovery.validate_checkpoint_for_successor(
            capability,
            validator_hotkey=item.auth.validator_hotkey,
            predecessor_directive_sha256=directive,
            minimum_finalized_block=180,
        )
    with pytest.raises(ValueError, match="closed"):
        recovery.validate_checkpoint_for_successor(
            capability,
            validator_hotkey=item.auth.validator_hotkey,
            predecessor_directive_sha256=directive,
            minimum_finalized_block=180,
        )
    assert not Path(installed.config.wallet.path).exists()


def test_caller_supplied_stopped_boolean_cannot_mint_checkpoint(explicit):
    with pytest.raises(ValueError, match="owned stopped-host lease"):
        _prepare(explicit)


def test_caller_supplied_observation_cannot_mint_checkpoint(explicit):
    with pytest.raises(ValueError, match="owned proof adapter"):
        recovery._check_owned(explicit.observation, explicit.stopped)


def test_owned_observation_cannot_predate_accepted_highwater(explicit, monkeypatch):
    from umi import competition_chain_state

    # The source verifier has its own tests; exercise this separate cross-component bound.
    monkeypatch.setattr(
        competition_chain_state, "validate_owned_weight_observation", lambda _: None
    )
    explicit.observation.block = explicit.stopped.accepted_at_finalized_block - 1
    with pytest.raises(ValueError, match="predates"):
        recovery._check_owned(explicit.observation, explicit.stopped)


def test_checkpoint_copy_preserves_exact_bytes_without_authority(trusted_ports):
    item = trusted_ports
    prepared = _prepare(item)
    destination = item.tmp_path / "second-archive"
    destination.mkdir(mode=0o700)
    try:
        copied = recovery.copy_retained_checkpoint_archive(
            Path(prepared.checkpoint_path),
            expected_sha256=prepared.checkpoint_sha256,
            owner=os.getuid(),
            destination_root=destination,
            destination_owner=os.getuid(),
            limits=item.limits,
        )
        body, objects = recovery.load_retained_checkpoint_archive(
            copied,
            expected_sha256=prepared.checkpoint_sha256,
            owner=os.getuid(),
            limits=item.limits,
        )
        assert copied.name == prepared.checkpoint_sha256 and objects
        assert not body.chain_submission_authorized
        assert Path(prepared.checkpoint_path).is_dir()
    finally:
        for path in destination.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)


@pytest.mark.parametrize(
    "phase", ["applied", "anchor_applied", "recovered_applied", "not_applied", "anchor_not_applied"]
)
def test_common_historical_recovery_after_sunset_keeps_missing_mortality_held(
    trusted_ports, monkeypatch, phase
):
    item = trusted_ports
    signed = _production_manifest()
    lease = _unsigned_production_lease(signed)
    root = item.tmp_path / "common"
    root.mkdir(mode=0o700)
    journal = _journal(item.auth.validator_hotkey)
    call = BootstrapExtrinsicReference(
        extrinsic_id=f"{SIMPLE_BLOCK + 1}-0001",
        block_number=SIMPLE_BLOCK + 1,
        extrinsic_index=1,
        block_hash="0x" + "99" * 32,
    )
    changes = {
        "phase": phase,
        "lease_sha256": hashlib.sha256(canonical_json_bytes(lease)).hexdigest(),
        "observation_block": SIMPLE_BLOCK + 2,
    }
    if phase == "applied":
        changes["weight_call"] = call
    elif phase == "anchor_applied":
        changes.update(anchor_call=call, manifest_anchor_block=call.block_number)
    elif phase == "anchor_not_applied":
        changes["manifest_anchor_block"] = None
    journal = journal.model_copy(update=changes)
    _write(root / "journal.json", journal)
    _write(root / "service.lock", b"")
    item.stopped.worker_state_root = root
    item.stopped.expected_manifest_sha256 = signed.manifest_sha256
    item.observation.block = lease.body.hard_sunset_block + 1000
    item.observation.validator_last_update = SIMPLE_BLOCK + 1
    item.observation.manifest_anchor_block = SIMPLE_BLOCK + 1
    item.observation.manifest_anchor_sha256 = signed.manifest_sha256
    item.observation.validator_row = tuple(tuple(row) for row in recovery._full_row(signed))
    seen = []

    def historical(value, **kwargs):
        # State-machine test only. The separate test below exercises rejection
        # of this unsigned fixture by the real historical signature verifier.
        assert value == lease and kwargs["signed_manifest"] == signed
        seen.append(kwargs["current_block"])

    monkeypatch.setattr(recovery, "verify_simple_bootstrap_lease", historical)
    prepared = _prepare(item, historical_manifests=(signed,), historical_leases=(lease,))
    assert seen and set(seen) == {SIMPLE_BLOCK}
    if phase in {"applied", "anchor_applied"}:
        assert prepared.prior_effects_reconciled
        _verify(item, prepared)
    else:
        assert not prepared.prior_effects_reconciled
        assert any("mortality" in reason for reason in prepared.holds)


def test_common_unsigned_historical_lease_is_never_accepted(explicit):
    item = explicit
    signed = _production_manifest()
    lease = _unsigned_production_lease(signed)
    journal = _journal(item.auth.validator_hotkey).model_copy(
        update={
            "lease_sha256": hashlib.sha256(canonical_json_bytes(lease)).hexdigest(),
        }
    )
    _write(item.root / "journal.json", journal)
    with (
        pytest.raises(ValueError, match="signature"),
        recovery.snapshot_legacy_bootstrap(
            item.root,
            **item.kwargs,
            historical_manifests=(signed,),
            historical_leases=(lease,),
        ),
    ):
        pytest.fail("unsigned historical lease was accepted")


def test_context_accumulation_stops_at_aggregate_bound(limits):
    bounded = limits.model_copy(update={"maximum_file_bytes": 4, "maximum_total_bytes": 8})
    with pytest.raises(ValueError, match="aggregate"):
        recovery._context_payloads((b"1234", b"5678"), (), SimpleNamespace(evidence=b"9"), bounded)


def test_verified_capability_binds_directory_entry_snapshot(trusted_ports):
    item = trusted_ports
    capability = _verify(item, _prepare(item))
    replacement = replace(capability._snapshot, _directory_entries={})
    forged = replace(capability, _snapshot=replacement)
    with pytest.raises(ValueError, match="capability"):
        recovery.validate_checkpoint_for_successor(
            forged,
            validator_hotkey=item.auth.validator_hotkey,
            predecessor_directive_sha256=item.stopped.accepted_directive_sha256,
            minimum_finalized_block=180,
        )


def test_terminal_recovery_never_reopens_inner_journal_through_legacy_helper(
    trusted_ports, monkeypatch
):
    from umi import validator_supervisor_worker

    def no_legacy_reads(*_args, **_kwargs):
        pytest.fail("recovery reopened legacy state outside its owned snapshot")

    monkeypatch.setattr(validator_supervisor_worker, "_load_canonical", no_legacy_reads)
    assert _prepare(trusted_ports).prior_effects_reconciled
