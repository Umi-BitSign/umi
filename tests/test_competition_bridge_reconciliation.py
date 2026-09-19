"""Pure reconciliation of valid histories with synthetic reader reports."""

import hashlib
from types import SimpleNamespace

import pytest

from tests.test_bridge_transactions import advance, idle, prepare
from tests.test_bridge_transactions import case as case
from tests.test_bridge_transactions import signed_policy as signed_policy
from tests.test_bridge_transactions import tx as tx
from tests.test_competition_bridge_recovery import completed as completed
from tests.test_competition_bridge_recovery import snapshot
from tests.test_competition_bridge_transactions import files_at, finish
from tests.test_competition_recovery import limits as limits
from tests.test_registration_bridge import replace_participant
from tests.test_simple_bootstrap_validator import (
    BLOCK as SIMPLE_BLOCK,
)
from tests.test_simple_bootstrap_validator import (
    _journal,
    _production_manifest,
    _unsigned_production_lease,
)
from umi import competition_recovery as recovery
from umi.bridge.receipts import VerifiedBridgeExpiry, VerifiedBridgeReceipt
from umi.bridge.transactions import RegistrationBridgeTransactionJournal, evolve_journal
from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_bridge_reconciliation import (
    bridge_outcomes_match_current_state,
    retained_outcomes_agree,
    summarize_bridge_outcome,
)
from umi.competition_bridge_recovery import HISTORY, JOURNAL, audit_bridge_history
from umi.protocol import canonical_json_bytes
from umi.registration_bridge import BootstrapExtrinsicReference, RegistrationBridgeState


def reports(audit):
    block = audit.current.attempt.era_death + 20
    ref = FinalizedSnapshotRef(block, "0x" + "11" * 32, "0x" + "22" * 32, "0x" + "33" * 32)
    items = []
    for path, journal in audit.attempts:
        if type(journal) is not RegistrationBridgeTransactionJournal:
            continue
        receipt = journal.weight_call or journal.failed_call
        if receipt:
            result = VerifiedBridgeReceipt(
                receipt, journal.failed_call is None, journal.signed_extrinsic_hash, ref
            )
        else:
            snapshot = ref
            if journal.expiry_observation:
                retained = journal.expiry_observation
                snapshot = FinalizedSnapshotRef(
                    retained.block_number, retained.block_hash, ref.parent_hash, retained.state_root
                )
            result = VerifiedBridgeExpiry(snapshot, journal.attempt.signing.nonce, ref)
        items.append(summarize_bridge_outcome(path, journal, result))
    return tuple(sorted(items, key=lambda item: item.path)), ref


def observation(journal, head):
    return SimpleNamespace(
        block=head.block_number,
        block_hash=head.block_hash,
        validator_uid=54,
        validator_last_update=journal.attempt.prior_last_update,
        validator_row=tuple(tuple(p) for p in journal.attempt.expected_row),
    )


@pytest.mark.parametrize("phase", ["applied", "failed", "expired_nonce_available"])
async def test_multiple_versioned_attempts_require_continuity(tmp_path, tx, phase):
    with RegistrationBridgeState(tmp_path / "writer") as state:
        prior = await finish(state, tx, phase)
        proven = await advance(tx.case, 250, nonce=8 if phase != "expired_nonce_available" else 7)
        if phase == "applied":
            tx.case.obs = replace_participant(
                tx.case.obs, 54, last_update=prior.weight_call.block_number
            )
        current = prepare(tx.policy, tx.case, proven, prior)
        state.store(current, archive=True)
    audit = audit_bridge_history(files_at(state.root), hotkey=current.validator_hotkey)
    outcomes, ref = reports(audit)
    owned = observation(current, ref)
    assert len(outcomes) == 2
    assert bridge_outcomes_match_current_state(audit, outcomes, owned)
    owned.validator_last_update += 1
    assert not bridge_outcomes_match_current_state(audit, outcomes, owned)
    with pytest.raises(ValueError, match="cover"):
        bridge_outcomes_match_current_state(audit, outcomes[:-1], owned)


async def test_mixed_legacy_history_uses_last_proven_row(tx, completed, tmp_path, limits):
    prior = completed.current
    proven = await advance(tx.case, 600)
    tx.case.obs = replace_participant(tx.case.obs, 54, last_update=prior.weight_call.block_number)
    tx.case.obs = tx.case.obs.model_copy(update={"validator_row": prior.attempt.expected_row})
    current = prepare(tx.policy, tx.case, proven, prior)
    files = dict(completed.files)
    files[f"{HISTORY}/{current.attempt.attempt_id}-preparing.json"] = canonical_json_bytes(current)
    files[JOURNAL] = canonical_json_bytes(current)
    audit = audit_bridge_history(files, hotkey=current.validator_hotkey)
    outcomes, ref = reports(audit)
    owned = observation(current, ref)
    owned.validator_row = tuple(tuple(p) for p in prior.attempt.expected_row)
    assert len(audit.attempts) == 3 and len(outcomes) == 1
    assert bridge_outcomes_match_current_state(audit, outcomes, owned)
    owned.commit_reveal_enabled = False
    with snapshot(
        tmp_path / "mixed-snapshot", SimpleNamespace(files=files, current=current), limits
    ) as snap:
        effects, holds = recovery._reconcile_snapshot(snap, owned, (), outcomes)
        assert not holds
        prior_effect = next(
            e for e in effects if e.minimum_effect_block == prior.weight_call.block_number
        )
        assert prior_effect.classification == "proven_current_weight"
    owned.validator_row = ()
    assert not bridge_outcomes_match_current_state(audit, outcomes, owned)


async def test_recollection_allows_only_forward_expiry_observation(tx, tmp_path):
    with RegistrationBridgeState(tmp_path / "writer") as state:
        current = await finish(state, tx, "preparing")
    audit = audit_bridge_history(files_at(state.root), hotkey=current.validator_hotkey)
    outcomes, _ = reports(audit)
    old = outcomes[0]
    fresh = old.model_copy(
        update={
            "resolution_block": old.resolution_block + 1,
            "verified_head_block": old.verified_head_block + 1,
            "resolution_block_hash": "0x" + "44" * 32,
            "verified_head_hash": "0x" + "44" * 32,
        }
    )
    retained_outcomes_agree([old], (fresh,))
    with pytest.raises(ValueError, match="rolled back"):
        retained_outcomes_agree([fresh], (old,))
    with pytest.raises(ValueError, match="changed"):
        retained_outcomes_agree(
            [old], (old.model_copy(update={"resolution_block_hash": "0x" + "55" * 32}),)
        )


@pytest.mark.parametrize("matching_row", [False, True])
async def test_expired_first_bridge_attempt_does_not_supersede_common_weights(
    tx, tmp_path, limits, monkeypatch, matching_row
):
    manifest = _production_manifest()
    lease = _unsigned_production_lease(manifest)
    call = BootstrapExtrinsicReference(
        extrinsic_id=f"{SIMPLE_BLOCK + 1}-0001",
        block_number=SIMPLE_BLOCK + 1,
        extrinsic_index=1,
        block_hash="0x" + "99" * 32,
    )
    old = _journal(tx.preparing.validator_hotkey).model_copy(
        update={
            "phase": "applied",
            "weight_call": call,
            "observation_block": SIMPLE_BLOCK + 2,
            "lease_sha256": hashlib.sha256(canonical_json_bytes(lease)).hexdigest(),
        }
    )
    tx.case.obs = replace_participant(tx.case.obs, 54, last_update=call.block_number)
    current = prepare(tx.policy, tx.case, tx.state, idle(tx.case.obs))
    raw = canonical_json_bytes(old)
    current = evolve_journal(current, legacy_journal_sha256=hashlib.sha256(raw).hexdigest())
    files = {
        "journal.json": raw,
        "registration-bridge-legacy-journal.json": raw,
        JOURNAL: canonical_json_bytes(current),
        f"{HISTORY}/{current.attempt.attempt_id}-preparing.json": canonical_json_bytes(current),
    }
    audit = audit_bridge_history(files, hotkey=current.validator_hotkey)
    outcomes, head = reports(audit)
    owned = observation(current, head)
    owned.commit_reveal_enabled = False
    owned.manifest_anchor_sha256 = manifest.manifest_sha256
    owned.manifest_anchor_block = call.block_number
    owned.validator_row = (
        tuple(tuple(p) for p in recovery._full_row(manifest)) if matching_row else ()
    )

    def historical(value, **kwargs):
        # Match the existing common-recovery state-machine fixture. Signature
        # rejection is covered separately; this test isolates row continuity.
        assert value == lease and kwargs["signed_manifest"] == manifest

    monkeypatch.setattr(recovery, "verify_simple_bootstrap_lease", historical)
    root = tmp_path / "common-worker"
    root.mkdir(mode=0o700)
    for path, payload in files.items():
        target = root / path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(payload)
        target.chmod(0o600)
    with recovery.snapshot_legacy_bootstrap(
        root,
        expected_hotkey=current.validator_hotkey,
        service_uid=root.stat().st_uid,
        accepted_sequence=1,
        accepted_directive_sha256="aa" * 32,
        accepted_at_finalized_block=1,
        config_sha256="bb" * 32,
        installation_sha256="cc" * 32,
        limits=limits,
        historical_manifests=(manifest,),
        historical_leases=(lease,),
    ) as snap:
        effects, holds = recovery._reconcile_snapshot(snap, owned, (manifest,), outcomes)
        if matching_row:
            assert not holds
            assert (
                next(e for e in effects if e.path == "journal.json").classification
                == "proven_current_weight"
            )
        else:
            assert "historical_weight_effect_not_proven" in holds
