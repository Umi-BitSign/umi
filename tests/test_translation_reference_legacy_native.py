"""Native-result type boundaries with real original files and checkpoint reuse.

Chain ports and receipt/expiry fixtures are synthetic. The shared native receipt
reader is qualified separately; these cases never submit or open a wallet.
"""

import json
import sys
from types import SimpleNamespace

import pytest

from tests.test_bridge_transactions import begin, idle, prepare
from tests.test_registration_bridge import BLOCK, replace_participant, signed_policy
from tests.test_translation_reference_state import read, reference_case, signing_case
from tests.test_translation_reference_transactions import advance
from umi.bootstrap_weight_operator import BootstrapExtrinsicReference
from umi.bridge.receipts import VerifiedBridgeExpiry, VerifiedBridgeReceipt
from umi.bridge.state import RegistrationBridgeState
from umi.bridge.transactions import BridgeSigningRecord, evolve_journal
from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_bridge_recovery import audit_bridge_history
from umi.encoding import datetime_to_unix_ms
from umi.protocol import canonical_json_bytes
from umi.translation_reference_legacy_native import (
    NativeLegacyOutcomeStore,
    approve_native_legacy,
)
from umi.translation_reference_legacy_state import ReferenceLegacyState
from umi.translation_reference_state import TranslationReferenceError
from umi.translation_reference_transactions import ReferenceWeightJournal

__all__ = ["reference_case", "signed_policy", "signing_case"]


async def original_attempt(case, signed_policy, root, phase):
    native = await case.reader._signing.read(case.obs.validator_hotkey)
    with RegistrationBridgeState(root) as original:
        previous = original.load()
        if previous is None:
            previous = idle(case.obs)
        preparing = prepare(signed_policy, case, native, previous)
        item = SimpleNamespace(case=case, preparing=preparing)
        # begin initializes only a genuinely new original journal.
        if original.load() is None:
            current = begin(
                original,
                item,
                phase if phase in {"preparing", "signed", "outcome_unknown"} else "submitting",
            )
        else:
            from tests.test_bridge_transactions import ENCODED
            from umi.bridge.transactions import retain_signed_extrinsic

            original.store(preparing, archive=True)
            current = retain_signed_extrinsic(preparing, ENCODED, now=case.now)
            original.store(current, archive=True)
            current = evolve_journal(current, phase="submitting")
            original.store(current, archive=True)
        if phase in {"applied", "failed", "receipt_returned"}:
            advance(
                case,
                case.head.number - BLOCK + 1,
                nonce=8,
            )
            receipt = BootstrapExtrinsicReference(
                extrinsic_id=f"{case.head.number}-0001",
                block_number=case.head.number,
                extrinsic_index=1,
                block_hash=case.head.block_hash,
            )
            update = dict(
                last_observed_block=case.head.number,
                last_observed_block_hash=case.head.block_hash,
                updated_at_unix_ms=datetime_to_unix_ms(case.now),
            )
            if phase == "failed":
                current = evolve_journal(current, phase="failed", failed_call=receipt, **update)
            else:
                current = evolve_journal(
                    current, phase="receipt_returned", weight_call=receipt, **update
                )
                original.store(current, archive=True)
                if phase == "applied":
                    current = evolve_journal(current, phase="applied")
        elif phase == "expired_nonce_available":
            advance(case, preparing.attempt.preflight_block + 8 - BLOCK)
            native = await case.reader._signing.read(case.obs.validator_hotkey)
            current = evolve_journal(
                current,
                phase=phase,
                expiry_observation=BridgeSigningRecord.from_state(native),
                last_observed_block=case.head.number,
                last_observed_block_hash=case.head.block_hash,
            )
        original.store(current, archive=True)
    last = (
        current.weight_call.block_number
        if current.weight_call
        else current.attempt.prior_last_update
    )
    case.updates[54] = last
    case.set_value("LastUpdate", case.updates)
    if current.weight_call:
        case.set_value("Weights", current.attempt.expected_row, 78, 54)
    case.obs = replace_participant(case.obs, 54, last_update=last)
    case.obs = case.obs.model_copy(update={"validator_row": current.attempt.expected_row})
    return current


class Receipts:
    def __init__(self, state):
        self.state = state
        self.calls = []
        self.fail_at = None

    async def find(self, journal):
        self.calls.append(("receipt", journal.attempt.attempt_id))
        if self.fail_at == len(self.calls):
            raise TimeoutError("interrupted native fixture")
        receipt = journal.weight_call or journal.failed_call
        if receipt is None:
            return None
        return VerifiedBridgeReceipt(
            receipt,
            journal.failed_call is None,
            journal.signed_extrinsic_hash,
            self.state.signing.runtime.snapshot,
        )

    async def expiry(self, journal):
        self.calls.append(("expiry", journal.attempt.attempt_id))
        snapshot = self.state.signing.runtime.snapshot
        if journal.expiry_observation is not None:
            old = journal.expiry_observation
            historical = FinalizedSnapshotRef(
                old.block_number, old.block_hash, snapshot.parent_hash, old.state_root
            )
            return VerifiedBridgeExpiry(historical, journal.attempt.signing.nonce, snapshot)
        return VerifiedBridgeExpiry(snapshot, journal.attempt.signing.nonce, snapshot)


async def gate(case, lease, journal, reader):
    return await approve_native_legacy(
        lease,
        await read(case),
        case.policy,
        journal,
        receipts=reader,
        verifier_semantics_sha256="a" * 64,
        now=case.now,
    )


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
async def test_original_v2_phases_use_native_results_and_warm_restart_reads_no_payloads(
    reference_case,
    signed_policy,
    tmp_path,
    phase,
):
    case = reference_case
    root = tmp_path / "original"
    original = await original_attempt(case, signed_policy, root, phase)
    advance(case, 30, nonce=8 if original.weight_call or original.failed_call else 7)
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    reader = Receipts(await read(case))
    with ReferenceLegacyState(root) as lease:
        journal = ReferenceWeightJournal(
            lease.follower_root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
        )
        result = await gate(case, lease, journal, reader)
        assert result["status"] == "native_v2_bridge_bound_to_current_state"
        assert result["native_v2_attempts"] == 1
        count = len(reader.calls)
    with ReferenceLegacyState(root) as restarted:
        assert await gate(case, restarted, journal, reader) == result
        assert restarted.payload_reads == 0
    assert len(reader.calls) == count
    assert {p: (root / p).read_bytes() for p in before} == before


@pytest.mark.asyncio
async def test_completed_attempts_resume_individually_after_interrupted_native_pass(
    reference_case,
    signed_policy,
    tmp_path,
):
    case = reference_case
    root = tmp_path / "original"
    await original_attempt(case, signed_policy, root, "applied")
    advance(case, 250, nonce=8)
    await original_attempt(case, signed_policy, root, "applied")
    advance(case, 270, nonce=9)
    reader = Receipts(await read(case))
    reader.fail_at = 2
    with ReferenceLegacyState(root) as lease:
        journal = ReferenceWeightJournal(
            lease.follower_root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
        )
        with pytest.raises(TimeoutError):
            await gate(case, lease, journal, reader)
    reader.fail_at = None
    before = len(reader.calls)
    with ReferenceLegacyState(root) as restarted:
        result = await gate(case, restarted, journal, reader)
    assert result["native_v2_attempts"] == 2
    assert len(reader.calls) - before == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["missing", "corrupt", "corrupt_result"])
async def test_missing_completion_repairs_original_verdict_without_native_recheck(
    reference_case,
    signed_policy,
    tmp_path,
    monkeypatch,
    damage,
):
    case = reference_case
    root = tmp_path / "original"
    await original_attempt(case, signed_policy, root, "applied")
    advance(case, 30, nonce=8)
    reader = Receipts(await read(case))
    with ReferenceLegacyState(root) as lease:
        journal = ReferenceWeightJournal(
            lease.follower_root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
        )
        retain = lease.retain_approval

        def interrupted(*_, **__):
            raise InterruptedError("interrupt before overall completion")

        monkeypatch.setattr(lease, "retain_approval", interrupted)
        with pytest.raises(InterruptedError):
            await gate(case, lease, journal, reader)
        store = NativeLegacyOutcomeStore(lease)
        complete = next(store.directory.glob("*.complete"))
        original = next(store.directory.glob("*.json"))
        if damage == "missing":
            complete.unlink()
        elif damage == "corrupt":
            complete.write_bytes(b'{"invalid":true}')
        else:
            data = json.loads(original.read_bytes())
            data["outcome"]["verified_head_block"] += 1
            original.write_bytes(canonical_json_bytes(data))
        before = len(reader.calls)
        with pytest.raises(TranslationReferenceError, match="repair_required"):
            await gate(case, lease, journal, reader)
        assert len(reader.calls) == before
        if damage == "corrupt_result":
            with pytest.raises(ValueError, match="checksum requires restoration"):
                store.repair_completions(hotkey=journal.hotkey)
            assert len(reader.calls) == before
            return
        interrupted = store.directory / ".pending-complete-crash-fixture"
        interrupted.write_bytes(b"interrupted bounded repair bytes")
        interrupted.chmod(0o600)
        store.repair_completions(hotkey=journal.hotkey)
        assert not interrupted.exists()
        store.repair_completions(hotkey=journal.hotkey)
        monkeypatch.setattr(lease, "retain_approval", retain)
        assert (await gate(case, lease, journal, reader))["native_v2_attempts"] == 1
        assert len(reader.calls) == before


@pytest.mark.asyncio
async def test_unrelated_native_current_update_does_not_reconcile_original_v2_history(
    reference_case,
    signed_policy,
    tmp_path,
):
    case = reference_case
    root = tmp_path / "original"
    original = await original_attempt(case, signed_policy, root, "applied")
    advance(case, 30, nonce=8)
    case.updates[54] = original.weight_call.block_number + 1
    case.set_value("LastUpdate", case.updates)
    reader = Receipts(await read(case))
    with ReferenceLegacyState(root) as lease:
        journal = ReferenceWeightJournal(
            lease.follower_root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
        )
        with pytest.raises(TranslationReferenceError, match="current_state_changed"):
            await gate(case, lease, journal, reader)
        assert journal.journal.get("reference_legacy_adoption", "accepted") is None
        audit = audit_bridge_history(lease.capture_files(), hotkey=journal.hotkey)
        assert audit.current == original


@pytest.mark.asyncio
async def test_rpc_shaped_expiry_cannot_create_native_recovery_authority(
    reference_case,
    signed_policy,
    tmp_path,
):
    case = reference_case
    root = tmp_path / "original"
    await original_attempt(case, signed_policy, root, "signed")
    advance(case, 30)
    reader = Receipts(await read(case))

    async def unproved(_):
        return {"nonce": 7, "finalized": True}

    reader.expiry = unproved
    with ReferenceLegacyState(root) as lease:
        journal = ReferenceWeightJournal(
            lease.follower_root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
        )
        with pytest.raises(ValueError, match="verified reader result"):
            await gate(case, lease, journal, reader)
        assert journal.journal.get("reference_legacy_adoption", "accepted") is None
        assert not list((lease.follower_root / "legacy-native-verification").glob("*.json"))


@pytest.mark.asyncio
async def test_lost_overall_legacy_completion_never_silently_reaudits_original_payloads(
    reference_case,
    signed_policy,
    tmp_path,
):
    case = reference_case
    root = tmp_path / "original"
    await original_attempt(case, signed_policy, root, "applied")
    advance(case, 30, nonce=8)
    reader = Receipts(await read(case))
    with ReferenceLegacyState(root) as lease:
        journal = ReferenceWeightJournal(
            lease.follower_root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
        )
        await gate(case, lease, journal, reader)
        with journal.journal.transaction() as db:
            db.execute("DELETE FROM records WHERE kind='reference_legacy_adoption'")
    before = len(reader.calls)
    with ReferenceLegacyState(root) as restarted:
        with pytest.raises(TranslationReferenceError, match="repair_required"):
            await gate(case, restarted, journal, reader)
        assert restarted.payload_reads == 0
    assert len(reader.calls) == before


def test_repair_requires_original_state_instead_of_creating_an_empty_replacement(
    tmp_path,
    monkeypatch,
):
    from umi.translation_reference_repair import main

    root = tmp_path / "absent-follower-state"
    monkeypatch.setattr(
        sys,
        "argv",
        ["repair", "--state-root", str(root), "--validator-hotkey", "unused-before-journal-lookup"],
    )
    with pytest.raises(ValueError, match="retained original lock and journal"):
        main()
    assert not root.exists()
