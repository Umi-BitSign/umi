"""Real local journal restart/atomicity tests with synthetic owned proof ports.

Retained encoded fixtures test storage only; they are never signed or submitted.
"""

from datetime import timedelta

import pytest

from tests.test_registration_bridge import BLOCK
from tests.test_translation_reference_state import read, reference_case, signing_case
from umi.chain import _header_hash
from umi.open_competition import digest
from umi.translation_reference_state import TranslationReferenceError
from umi.translation_reference_transactions import ReferenceWeightJournal, reference_weight_intent

__all__ = ["reference_case", "signing_case"]


def journal(root, case, maximum_bytes=4 * 1024**2):
    return ReferenceWeightJournal(
        root, validator_hotkey=case.obs.validator_hotkey, maximum_bytes=maximum_bytes
    )


def advance(case, blocks, nonce=7):
    case.header["number"] = BLOCK + blocks
    block_hash = _header_hash(case.header, "fixture")
    case.obs = case.obs.model_copy(
        update={"block_number": BLOCK + blocks, "block_hash": block_hash}
    )
    case.head.number, case.head.block_hash = BLOCK + blocks, block_hash
    case.values[case.account_key] = f'{{"nonce":{nonce}}}'.encode()


@pytest.mark.asyncio
async def test_crash_restart_keeps_exact_pending_signature_and_cannot_reserve_another(
    reference_case, tmp_path
):
    case = reference_case
    state = await read(case)
    intent = reference_weight_intent(state, case.policy, now=case.now, previous_intent_sha256=None)
    root = tmp_path / "worker"
    writer = journal(root, case)
    assert writer.pending() is None
    first = writer.reserve(intent)
    assert first.intent == intent and first.signed is None
    assert writer.reserve(intent) == first
    retained = writer.retain_signed(intent, b"retained-synthetic-encoded-envelope")
    resumed = journal(root, case)
    assert resumed.pending() == retained
    advance(case, 1)
    other = reference_weight_intent(
        await read(case), case.policy, now=case.now, previous_intent_sha256=digest(intent)
    )
    with pytest.raises(ValueError, match="requires native reconciliation"):
        resumed.reserve(other)
    assert resumed.pending() == retained


@pytest.mark.asyncio
async def test_fresh_expiry_fences_original_bytes_without_claiming_failure_or_rebroadcast(
    reference_case, tmp_path
):
    case = reference_case
    writer = journal(tmp_path / "worker", case)
    state = await read(case)
    intent = reference_weight_intent(state, case.policy, now=case.now, previous_intent_sha256=None)
    writer.reserve(intent)
    writer.retain_signed(intent, b"one-original-envelope")
    with pytest.raises(ValueError, match="era has not ended"):
        writer.fence_expired(state.signing, now=case.now)
    advance(case, 8, nonce=8)
    state = await read(case)
    end = writer.fence_expired(state.signing, now=case.now)
    assert end.end.reason == "expired_outcome_unknown"
    assert not end.end.original_success_or_failure_claimed
    assert writer.fence_expired(state.signing, now=case.now) == end
    successor = reference_weight_intent(
        state, case.policy, now=case.now, previous_intent_sha256=digest(intent)
    )
    next_pending = writer.reserve(successor)
    assert next_pending.intent == successor and next_pending.signed is None
    assert (
        writer.journal.get("reference_weight_signed", digest(intent))["encoded"]
        == b"one-original-envelope".hex()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["missing", "stale_count", "missing_intent"])
async def test_damaged_head_is_an_explicit_repair_failure_instead_of_empty_state(
    reference_case, tmp_path, damage
):
    case = reference_case
    root = tmp_path / "worker"
    writer = journal(root, case)
    intent = reference_weight_intent(
        await read(case), case.policy, now=case.now, previous_intent_sha256=None
    )
    writer.reserve(intent)
    with writer.journal.transaction() as db:
        if damage == "missing":
            db.execute("DROP TABLE reference_head")
        elif damage == "stale_count":
            db.execute("UPDATE reference_head SET number=0")
        else:
            db.execute("UPDATE reference_head SET intent=?", ("00" * 32,))
    with pytest.raises(ValueError, match="repair required"):
        journal(root, case)


@pytest.mark.asyncio
async def test_capacity_increase_and_repeat_upgrade_preserve_attempt_and_lock(
    reference_case, tmp_path
):
    case = reference_case
    root = tmp_path / "worker"
    writer = journal(root, case)
    intent = reference_weight_intent(
        await read(case), case.policy, now=case.now, previous_intent_sha256=None
    )
    original = writer.reserve(intent)
    inode = writer.journal.lock_path.stat().st_ino
    assert journal(root, case, 8 * 1024**2).pending() == original
    assert journal(root, case, 8 * 1024**2).journal.lock_path.stat().st_ino == inode
    assert writer.pending() == original


@pytest.mark.asyncio
async def test_expiry_uses_signing_proof_without_requiring_a_new_active_reference(
    reference_case, tmp_path
):
    case = reference_case
    writer = journal(tmp_path / "worker", case)
    intent = reference_weight_intent(
        await read(case), case.policy, now=case.now, previous_intent_sha256=None
    )
    writer.reserve(intent)
    advance(case, 8)
    # Reconciliation uses its own signing proof, even if the reference currently
    # cannot authorize selection of another row. No old authority is reactivated.
    case.active[200] = False
    case.set_value("Active", case.active)
    signing = await case.reader._signing.read(case.obs.validator_hotkey)
    assert writer.fence_expired(signing, now=case.now).end is not None
    with pytest.raises(ValueError, match="snapshot is stale"):
        writer.fence_expired(signing, now=case.now + timedelta(seconds=121))


@pytest.mark.asyncio
async def test_index_repair_is_atomic_counted_and_keeps_original_signed_bytes(
    reference_case, tmp_path
):
    case = reference_case
    root = tmp_path / "worker"
    writer = journal(root, case)
    intent = reference_weight_intent(
        await read(case), case.policy, now=case.now, previous_intent_sha256=None
    )
    writer.reserve(intent)
    first = writer.retain_signed(intent, b"original-retained-transaction")
    with writer.journal.transaction() as db:
        db.execute("DROP TABLE reference_head")
    events = []
    repaired = ReferenceWeightJournal(
        root,
        validator_hotkey=case.obs.validator_hotkey,
        maximum_bytes=8 * 1024**2,
        repair_head_index=True,
        progress=events.append,
    )
    assert repaired.pending() == first
    assert events[-1]["completed"] == events[-1]["total"] == 1
    assert events[-1]["eta_seconds"] == 0
    inode = repaired.journal.lock_path.stat().st_ino
    repeated = ReferenceWeightJournal(
        root,
        validator_hotkey=case.obs.validator_hotkey,
        maximum_bytes=8 * 1024**2,
        repair_head_index=True,
    )
    assert repeated.pending() == first
    assert repeated.journal.lock_path.stat().st_ino == inode


@pytest.mark.asyncio
async def test_interrupted_index_repair_can_resume_without_resetting_the_attempt(
    reference_case, tmp_path
):
    case = reference_case
    root = tmp_path / "worker"
    writer = journal(root, case)
    intent = reference_weight_intent(
        await read(case), case.policy, now=case.now, previous_intent_sha256=None
    )
    pending = writer.reserve(intent)
    with writer.journal.transaction() as db:
        db.execute("DROP TABLE reference_head")

    def interrupt(event):
        if event["state"] == "running" and event["completed"]:
            raise RuntimeError("injected interruption")

    with pytest.raises(RuntimeError, match="injected interruption"):
        ReferenceWeightJournal(
            root,
            validator_hotkey=case.obs.validator_hotkey,
            maximum_bytes=4 * 1024**2,
            repair_head_index=True,
            progress=interrupt,
        )
    with pytest.raises(ValueError, match="repair required"):
        journal(root, case)
    repaired = ReferenceWeightJournal(
        root,
        validator_hotkey=case.obs.validator_hotkey,
        maximum_bytes=4 * 1024**2,
        repair_head_index=True,
    )
    assert repaired.pending() == pending


@pytest.mark.asyncio
async def test_intent_reserves_the_signed_policy_submission_freshness_budget(reference_case):
    case = reference_case
    state = await read(case)
    with pytest.raises(TranslationReferenceError, match="freshness_headroom_insufficient"):
        reference_weight_intent(
            state, case.policy, now=case.now + timedelta(seconds=61), previous_intent_sha256=None
        )
