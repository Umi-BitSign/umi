"""Versioned archive integration with explicit synthetic authority/proof ports."""

import fcntl
import hashlib
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_bridge_transactions import case as case
from tests.test_bridge_transactions import signed_policy as signed_policy
from tests.test_bridge_transactions import tx as tx
from tests.test_competition_bridge_transactions import finish
from tests.test_competition_recovery import limits as limits
from umi import competition_host_anchor as anchor
from umi import competition_initial_upgrade as upgrade
from umi import competition_recovery as recovery
from umi import competition_recovery_observation as owner
from umi.bridge.receipts import VerifiedBridgeExpiry, VerifiedBridgeReceipt
from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_bridge_reconciliation import summarize_bridge_outcome
from umi.competition_bridge_recovery import JOURNAL
from umi.protocol import canonical_json_bytes
from umi.registration_bridge import BootstrapExtrinsicReference, RegistrationBridgeState


@pytest.fixture
async def checkpoint_case(tmp_path, tx, limits, monkeypatch, request):
    phase = getattr(request, "param", "submitting")
    root, archives, supervisor = (tmp_path / n for n in ("writer", "archives", "supervisor"))
    archives.mkdir(mode=0o700)
    supervisor.mkdir(mode=0o700)
    with RegistrationBridgeState(root) as state:
        journal = await finish(state, tx, phase)
    block = journal.last_observed_block + 20
    ref = FinalizedSnapshotRef(block, "0x" + "66" * 32, "0x" + "55" * 32, "0x" + "77" * 32)
    if phase in {"preparing", "signed", "expired_nonce_available"}:
        retained = journal.expiry_observation
        expiry = (
            ref
            if retained is None
            else FinalizedSnapshotRef(
                retained.block_number, retained.block_hash, "0x" + "55" * 32, retained.state_root
            )
        )
        result = VerifiedBridgeExpiry(expiry, journal.attempt.signing.nonce, ref)
    else:
        receipt = (
            journal.weight_call
            or journal.failed_call
            or BootstrapExtrinsicReference(
                extrinsic_id=f"{journal.attempt.preflight_block + 1}-0001",
                block_number=journal.attempt.preflight_block + 1,
                extrinsic_index=1,
                block_hash="0x" + "22" * 32,
            )
        )
        result = VerifiedBridgeReceipt(
            receipt, phase != "failed", journal.signed_extrinsic_hash, ref
        )
    outcome = summarize_bridge_outcome(JOURNAL, journal, result)
    stopped = SimpleNamespace(
        worker_state_root=root,
        state_root=supervisor,
        validator_hotkey=journal.validator_hotkey,
        service_uid=root.stat().st_uid,
        accepted_sequence=10,
        accepted_directive_sha256="33" * 32,
        accepted_at_finalized_block=journal.attempt.preflight_block - 1,
        config_sha256="44" * 32,
        installation_sha256="55" * 32,
        expected_manifest_sha256=None,
        expected_registration_bridge_policy_sha256=journal.attempt.policy_sha256,
        _binding="test-stopped",
        live=True,
    )
    evidence = canonical_json_bytes({"synthetic": True, "block": block})
    obs = SimpleNamespace(
        block=block,
        block_hash=ref.block_hash,
        genesis_hash="0x" + "88" * 32,
        chain_config_sha256="99" * 32,
        validator_hotkey=journal.validator_hotkey,
        validator_uid=54,
        validator_last_update=outcome.resolution_block
        if outcome.disposition == "applied"
        else journal.attempt.prior_last_update,
        validator_row=tuple(tuple(p) for p in journal.attempt.expected_row)
        if outcome.disposition == "applied"
        else (),
        commit_reveal_enabled=False,
        evidence=evidence,
        evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        _binding="test-owned",
    )

    def check_stopped(value=stopped):
        assert value is stopped
        if not stopped.live:
            raise ValueError("stopped lease ended")

    def check_owned(value):
        assert value is obs

    stopped.recheck_stopped = check_stopped
    monkeypatch.setattr(recovery, "_check_stopped", check_stopped)
    monkeypatch.setattr(
        recovery, "_check_owned", lambda value, host: (check_stopped(host), check_owned(value))
    )
    monkeypatch.setattr(owner, "validate_owned_weight_observation", check_owned)
    with recovery.snapshot_legacy_bootstrap(
        root, **recovery._snapshot_kwargs(stopped, limits, (), ())
    ) as snap:
        collected = owner.StoppedBridgeObservation(obs, snap.sha256, (outcome,), stopped)
    # Explicit fixture authority. Separate observer tests cover actual issuance;
    # a parsed/constructed object alone must never pass the registry check.
    owner._BRIDGE_OBSERVATIONS[collected] = owner._bridge_binding(collected)
    item = SimpleNamespace(
        root=root,
        archives=archives,
        journal=journal,
        stopped=stopped,
        observation=obs,
        collected=collected,
        limits=limits,
        outcome=outcome,
    )
    item.prepare = lambda **kw: recovery.prepare_recovery_checkpoint(
        stopped, obs, destination_root=archives, limits=limits, **kw
    )
    item.verify = lambda prepared, **kw: recovery.verify_recovery_checkpoint(
        Path(prepared.checkpoint_path),
        expected_checkpoint_sha256=prepared.checkpoint_sha256,
        stopped=stopped,
        observation=obs,
        limits=limits,
        **kw,
    )
    return item


@pytest.mark.parametrize(
    "checkpoint_case",
    [
        "preparing",
        "signed",
        "submitting",
        "outcome_unknown",
        "receipt_returned",
        "applied",
        "failed",
        "expired_nonce_available",
    ],
    indirect=True,
)
async def test_each_phase_checkpoints_only_with_collected_outcomes(checkpoint_case):
    item = checkpoint_case
    before = {p: p.read_bytes() for p in item.root.rglob("*") if p.is_file()}
    held = item.prepare()
    assert not held.prior_effects_reconciled
    assert "registration_bridge_transaction_proof_required" in held.holds
    prepared = item.prepare(bridge_observation=item.collected)
    assert prepared.prior_effects_reconciled and not prepared.holds
    body, _ = recovery.load_retained_checkpoint_archive(
        Path(prepared.checkpoint_path),
        expected_sha256=prepared.checkpoint_sha256,
        owner=item.stopped.service_uid,
        limits=item.limits,
    )
    assert body.schema_ == "umi-successor-recovery-checkpoint/2"
    assert body.bridge_outcomes == [item.outcome]
    assert not body.chain_submission_authorized and not body.pending_queue_absence_proven
    with pytest.raises(ValueError, match="recollected"):
        item.verify(prepared)
    result = item.verify(prepared, bridge_observation=item.collected)
    recovery.validate_checkpoint_for_successor(
        result,
        validator_hotkey=item.journal.validator_hotkey,
        predecessor_directive_sha256=item.stopped.accepted_directive_sha256,
        minimum_finalized_block=item.observation.block,
    )
    assert before == {p: p.read_bytes() for p in before}
    item.stopped.live = False
    with pytest.raises(ValueError, match="lease ended"):
        recovery.validate_checkpoint_for_successor(
            result,
            validator_hotkey=item.journal.validator_hotkey,
            predecessor_directive_sha256=item.stopped.accepted_directive_sha256,
            minimum_finalized_block=item.observation.block,
        )


@pytest.mark.parametrize("change", ["constructed", "snapshot", "outcomes"])
async def test_operator_objects_and_changed_capabilities_cannot_clear_hold(checkpoint_case, change):
    item = checkpoint_case
    forged = replace(item.collected)
    if change == "snapshot":
        forged = item.collected
        object.__setattr__(forged, "snapshot_sha256", "aa" * 32)
    elif change == "outcomes":
        forged = item.collected
        object.__setattr__(forged, "outcomes", ())
    with pytest.raises(ValueError, match="absent, altered or misbound"):
        item.prepare(bridge_observation=forged)


@pytest.mark.parametrize("change", ["uid", "row", "last_update", "commit_reveal"])
async def test_fresh_chain_mismatch_retains_holds(checkpoint_case, change):
    item = checkpoint_case
    if change == "uid":
        item.observation.validator_uid = 55
    elif change == "row":
        item.observation.validator_row = ()
    elif change == "last_update":
        item.observation.validator_last_update += 1
    else:
        item.observation.commit_reveal_enabled = True
    assert not item.prepare(bridge_observation=item.collected).prior_effects_reconciled


@pytest.mark.parametrize("change", ["disposition", "receipt", "effect"])
async def test_rehashed_operator_archive_cannot_replace_proven_outcomes(checkpoint_case, change):
    item = checkpoint_case
    prepared = item.prepare(bridge_observation=item.collected)
    body, objects = recovery.load_retained_checkpoint_archive(
        Path(prepared.checkpoint_path),
        expected_sha256=prepared.checkpoint_sha256,
        owner=item.stopped.service_uid,
        limits=item.limits,
    )
    if change == "effect":
        body = body.model_copy(
            update={
                "reconciled_effects": [
                    effect.model_copy(update={"reason": "operator_claim"})
                    for effect in body.reconciled_effects
                ]
            }
        )
    else:
        changes = (
            {"disposition": "failed"}
            if change == "disposition"
            else {"resolution_block": item.outcome.resolution_block + 1}
        )
        body = body.model_copy(
            update={"bridge_outcomes": [item.outcome.model_copy(update=changes)]}
        )
    target = recovery._archive(body, objects, item.archives, item.stopped.service_uid, item.limits)
    forged = prepared.model_copy(
        update={"checkpoint_path": str(target), "checkpoint_sha256": target.name}
    )
    with pytest.raises(ValueError, match=r"recollected bridge|effect report"):
        item.verify(forged, bridge_observation=item.collected)


async def test_copied_archive_preserves_bytes_but_does_not_issue_authority(
    checkpoint_case, tmp_path
):
    item = checkpoint_case
    prepared = item.prepare(bridge_observation=item.collected)
    destination = tmp_path / "retained-copy"
    destination.mkdir(mode=0o700)
    target = recovery.copy_retained_checkpoint_archive(
        Path(prepared.checkpoint_path),
        expected_sha256=prepared.checkpoint_sha256,
        owner=item.stopped.service_uid,
        destination_root=destination,
        destination_owner=item.stopped.service_uid,
        limits=item.limits,
    )
    copied = prepared.model_copy(update={"checkpoint_path": str(target)})
    assert recovery.load_recovery_checkpoint_context(
        target,
        expected_sha256=prepared.checkpoint_sha256,
        owner=item.stopped.service_uid,
        limits=item.limits,
    ) == ((), ())
    with pytest.raises(ValueError, match="recollected"):
        item.verify(copied)
    assert (
        item.verify(copied, bridge_observation=item.collected).checkpoint_sha256
        == prepared.checkpoint_sha256
    )


async def test_installed_readonly_archive_preserves_versioned_outcomes(checkpoint_case, tmp_path):
    item = checkpoint_case
    prepared = item.prepare(bridge_observation=item.collected)
    body, objects = recovery.load_retained_checkpoint_archive(
        Path(prepared.checkpoint_path),
        expected_sha256=prepared.checkpoint_sha256,
        owner=item.stopped.service_uid,
        limits=item.limits,
    )
    root = tmp_path / "installed-anchor"
    root.mkdir(mode=0o700)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        anchor._write_installed_recovery(descriptor, prepared.checkpoint_sha256, body, objects)
    finally:
        os.close(descriptor)
    path = root / anchor.activation.RECOVERY_DIRECTORY_NAME / prepared.checkpoint_sha256
    installed, retained = recovery.load_installed_retained_checkpoint_archive(
        path,
        expected_sha256=prepared.checkpoint_sha256,
        owner=item.stopped.service_uid,
        limits=item.limits,
    )
    assert installed == body and retained == objects
    assert installed.schema_ == "umi-successor-recovery-checkpoint/2"
    assert canonical_json_bytes(installed) == canonical_json_bytes(body)
    assert not installed.chain_submission_authorized


@pytest.mark.parametrize("mutate", [False, True])
async def test_initial_observation_holds_snapshot_locks_and_rechecks_bytes(checkpoint_case, mutate):
    item = checkpoint_case
    lock_paths = list(item.root.glob("*.lock"))
    assert lock_paths

    class Observer:
        async def observe_bridge(self, audit, snapshot_sha256):
            assert audit.current == item.journal
            assert snapshot_sha256 == item.collected.snapshot_sha256
            for path in lock_paths:
                descriptor = os.open(path, os.O_RDONLY)
                try:
                    with pytest.raises(BlockingIOError):
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(descriptor)
            if mutate:
                (item.root / JOURNAL).write_bytes(b"altered during proof collection")
            return item.collected

    if mutate:
        with pytest.raises(ValueError, match=r"changed|different"):
            await upgrade._observe_stopped_history(item.stopped, Observer(), item.limits)
    else:
        observation, collected = await upgrade._observe_stopped_history(
            item.stopped, Observer(), item.limits
        )
        assert observation is item.observation and collected is item.collected
