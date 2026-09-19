"""Stopped-state audits retain v2 claims without granting chain authority."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests.test_bridge_signing import case as case
from tests.test_bridge_transactions import advance, begin, prepare
from tests.test_bridge_transactions import tx as tx
from tests.test_competition_bridge_recovery import completed as completed
from tests.test_competition_bridge_recovery import snapshot
from tests.test_competition_recovery import limits as limits
from tests.test_registration_bridge import replace_participant
from tests.test_registration_bridge import signed_policy as signed_policy
from umi import competition_recovery as recovery
from umi import registration_bridge as bridge
from umi.bridge.journal_history import audit_attempt_phases
from umi.bridge.transactions import (
    evolve_journal,
    parse_bridge_journal,
    reconcile_transaction_journal,
)
from umi.competition_bridge_recovery import HISTORY, JOURNAL, audit_bridge_history
from umi.protocol import canonical_json_bytes


def files_at(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


async def finish(state, tx, phase):
    journal = begin(
        state, tx, phase if phase in {"preparing", "signed", "outcome_unknown"} else "submitting"
    )
    if phase in {"receipt_returned", "applied", "failed"}:
        await advance(tx.case, 1, nonce=8)
        receipt = bridge.BootstrapExtrinsicReference(
            extrinsic_id=f"{tx.case.obs.block_number}-0001",
            block_number=tx.case.obs.block_number,
            extrinsic_index=1,
            block_hash=tx.case.obs.block_hash,
        )
        updates = dict(
            last_observed_block=tx.case.obs.block_number,
            last_observed_block_hash=tx.case.obs.block_hash,
        )
        if phase == "failed":
            journal = evolve_journal(journal, phase="failed", failed_call=receipt, **updates)
        else:
            journal = evolve_journal(
                journal, phase="receipt_returned", weight_call=receipt, **updates
            )
            state.store(journal, archive=True)
            if phase == "applied":
                journal = evolve_journal(journal, phase="applied")
    elif phase == "expired_nonce_available":
        proven = await advance(tx.case)
        journal = reconcile_transaction_journal(
            journal, tx.case.obs, now=tx.case.now, signing_state=proven
        )
    state.store(journal, archive=True)
    return journal


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "phase",
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
)
async def test_each_versioned_phase_is_preserved_and_needs_chain_proof(tmp_path, tx, limits, phase):
    root = tmp_path.resolve() / "writer"
    with bridge.RegistrationBridgeState(root) as state:
        current = await finish(state, tx, phase)
    files = files_at(root)
    before = dict(files)
    audited = audit_bridge_history(files, hotkey=current.validator_hotkey)
    assert audited.current == current
    assert audited.attempts == ((JOURNAL, current),)
    assert audited.holds == ("registration_bridge_transaction_proof_required",)
    assert files == before
    owned = SimpleNamespace(
        block=current.last_observed_block + 1,
        block_hash="0x" + "55" * 32,
        validator_row=tuple(tuple(pair) for pair in current.attempt.expected_row),
        validator_last_update=current.weight_call.block_number
        if current.weight_call
        else current.attempt.prior_last_update,
        validator_uid=54,
        commit_reveal_enabled=False,
    )
    item = SimpleNamespace(files=files, current=current)
    with snapshot(tmp_path / "snapshot", item, limits) as snap:
        assert snap._files == before
        assert snap.manifest.effects[0].reason == "registration_bridge_transaction_proof_required"
        _, holds = recovery._reconcile_snapshot(snap, owned, ())
        assert "registration_bridge_transaction_proof_required" in holds
    assert files_at(root) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["preparing", "signed", "submitting", "receipt_returned"])
async def test_versioned_handoff_rejects_missing_durable_transition(tmp_path, tx, missing):
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "writer") as state:
        current = await finish(state, tx, "applied")
        files = files_at(state.root)
    del files[f"{HISTORY}/{current.attempt.attempt_id}-{missing}.json"]
    with pytest.raises(ValueError, match=r"missing|transition"):
        audit_bridge_history(files, hotkey=current.validator_hotkey)


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["failed", "expired_nonce_available"])
@pytest.mark.parametrize("gap", [False, True])
async def test_nonwriting_attempt_preserves_lastupdate_continuity(tmp_path, tx, phase, gap):
    root = tmp_path.resolve() / "writer"
    with bridge.RegistrationBridgeState(root) as state:
        prior = await finish(state, tx, phase)
        proven = await advance(tx.case, 250, nonce=8 if phase == "failed" else 7)
        if gap:
            tx.case.obs = replace_participant(
                tx.case.obs, 54, last_update=prior.last_observed_block + 1
            )
        current = prepare(tx.policy, tx.case, proven, prior)
        state.store(current, archive=True)
    if gap:
        with pytest.raises(ValueError, match="LastUpdate gap"):
            audit_bridge_history(files_at(root), hotkey=current.validator_hotkey)
    else:
        audit = audit_bridge_history(files_at(root), hotkey=current.validator_hotkey)
        assert len(audit.attempts) == 2
        assert audit.attempts[0][1] == prior
        assert audit.holds == ("registration_bridge_transaction_proof_required",)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    ["current_bytes", "current_receipt", "current_rollback", "downgrade", "history_binding"],
)
async def test_versioned_handoff_rejects_changed_history(tmp_path, tx, mutation):
    root = tmp_path.resolve() / "writer"
    with bridge.RegistrationBridgeState(root) as state:
        current = await finish(state, tx, "applied")
    files = files_at(root)
    if mutation == "current_bytes":
        raw = b"different-fixture-bytes"
        from umi.signed_extrinsic import exact_signed_extrinsic

        current = evolve_journal(
            current,
            signed_extrinsic=raw.hex(),
            signed_extrinsic_hash=exact_signed_extrinsic(raw).extrinsic_hash,
        )
    elif mutation == "current_receipt":
        current = evolve_journal(
            current,
            weight_call=current.weight_call.model_copy(
                update={
                    "extrinsic_index": 2,
                    "extrinsic_id": f"{current.weight_call.block_number}-0002",
                }
            ),
        )
    elif mutation == "current_rollback":
        current = parse_bridge_journal(
            files[f"{HISTORY}/{current.attempt.attempt_id}-submitting.json"]
        )
    elif mutation == "downgrade":
        from tests.test_competition_bridge_recovery import add_attempt
        from tests.test_registration_bridge import replace_participant

        obs = replace_participant(
            tx.case.obs.model_copy(update={"block_number": tx.case.obs.block_number + 250}),
            54,
            last_update=current.weight_call.block_number,
        )
        add_attempt(files, tx.policy, obs)
    else:
        path = f"{HISTORY}/{current.attempt.attempt_id}-signed.json"
        original = parse_bridge_journal(files[path])
        files[path] = canonical_json_bytes(
            evolve_journal(original, legacy_journal_sha256="aa" * 32)
        )
    if mutation != "downgrade":
        files[JOURNAL] = canonical_json_bytes(current)
    with pytest.raises(ValueError):
        audit_bridge_history(files, hotkey=current.validator_hotkey)


def test_shared_auditor_rejects_mislabeled_phase(tx):
    with pytest.raises(bridge.RegistrationBridgeError, match="phase_identity"):
        audit_attempt_phases({"submitting": tx.preparing})


@pytest.mark.asyncio
async def test_mixed_legacy_and_versioned_history_preserves_old_bytes(tx, completed):
    prior = completed.current
    proven = await advance(tx.case, 600)
    tx.case.obs = replace_participant(tx.case.obs, 54, last_update=prior.weight_call.block_number)
    tx.case.obs = tx.case.obs.model_copy(update={"validator_row": prior.attempt.expected_row})
    current = prepare(tx.policy, tx.case, proven, prior)
    files = dict(completed.files)
    files[f"{HISTORY}/{current.attempt.attempt_id}-preparing.json"] = canonical_json_bytes(current)
    files[JOURNAL] = canonical_json_bytes(current)
    audit = audit_bridge_history(files, hotkey=current.validator_hotkey)
    assert len(audit.attempts) == 3
    assert audit.attempts[-1] == (JOURNAL, current)
    assert audit.holds == ("registration_bridge_transaction_proof_required",)
    assert all(files[path] == raw for path, raw in completed.files.items() if path != JOURNAL)


def test_shared_auditor_rejects_skipped_legacy_receipt(completed):
    records = {
        phase: parse_bridge_journal(
            completed.files[f"{HISTORY}/{completed.current.attempt.attempt_id}-{phase}.json"]
        )
        for phase in ("submitting", "applied")
    }
    with pytest.raises(bridge.RegistrationBridgeError, match="applied_receipt_missing"):
        audit_attempt_phases(records)
