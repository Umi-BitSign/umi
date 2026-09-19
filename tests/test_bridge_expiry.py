"""Historical nonce reads use authenticated headers and account proofs."""

import asyncio
import json

import pytest

from tests.test_bridge_receipts import history as history
from tests.test_bridge_receipts import journal_at
from tests.test_bridge_transactions import case as case
from tests.test_bridge_transactions import signed_policy as signed_policy
from tests.test_bridge_transactions import tx as tx
from umi.bridge.policy import RegistrationBridgeError
from umi.bridge.transactions import evolve_journal
from umi.protocol import canonical_json_bytes


def expired(history, tx):
    block = history.birth + 10
    ref_hash = history.hashes[block]
    return evolve_journal(
        history.journal,
        phase="expired_nonce_available",
        last_observed_block=block,
        last_observed_block_hash=ref_hash,
        expiry_observation=tx.preparing.attempt.signing.model_copy(
            update={
                "block_number": block,
                "block_hash": ref_hash,
                "state_root": history.headers[ref_hash]["stateRoot"],
            }
        ),
    )


@pytest.mark.asyncio
async def test_historical_expiry_uses_proven_old_nonce_after_later_transactions(history, tx):
    journal = expired(history, tx)
    before = canonical_json_bytes(journal)
    history.head = history.birth + 200
    state_root = history.headers[history.hashes[history.head]]["stateRoot"]
    history.values[state_root][b"System.Account"] = b'{"nonce": 100}'
    result = await history.reader.expiry(journal)
    assert result.snapshot.block_number == journal.expiry_observation.block_number
    assert result.nonce == journal.attempt.signing.nonce
    assert result.owned_head.block_number == history.head
    assert history.reader._cursor.snapshot.block_number == history.birth
    calls = len(history.calls)
    assert await history.reader.expiry(journal) == result
    assert len(history.calls) == calls
    assert canonical_json_bytes(journal) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["preparing", "signed", "submitting", "outcome_unknown"])
async def test_unresolved_attempt_can_prove_nonce_available_after_era(history, tx, phase):
    original = tx.preparing if phase == "preparing" else history.journal
    journal = evolve_journal(original, phase=phase)
    with pytest.raises(RegistrationBridgeError, match="not_finalized"):
        await history.reader.expiry(journal)
    history.head += 1
    result = await history.reader.expiry(journal)
    assert result.snapshot.block_number == journal.attempt.era_death
    assert result.nonce == journal.attempt.signing.nonce


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["block_hash", "state_root"])
async def test_local_expiry_identity_cannot_select_fork(history, tx, field):
    journal = expired(history, tx)
    journal = evolve_journal(
        journal,
        expiry_observation=journal.expiry_observation.model_copy(update={field: "0x" + "11" * 32}),
        last_observed_block=history.birth + 20,
    )
    history.head = history.birth + 30
    executions = list(tx.case.executed)
    with pytest.raises(RegistrationBridgeError, match="ancestry_mismatch"):
        await history.reader.expiry(journal)
    assert tx.case.executed == executions


@pytest.mark.asyncio
@pytest.mark.parametrize("nonce", [8, -1, 2**32, True, "7", None])
async def test_nonce_must_be_proven_exact_original_u32(history, tx, nonce):
    journal = expired(history, tx)
    history.head = history.birth + 20
    history.values[journal.expiry_observation.state_root][b"System.Account"] = json.dumps(
        {"nonce": nonce}
    ).encode()
    with pytest.raises(RegistrationBridgeError, match="nonce_unavailable"):
        await history.reader.expiry(journal)


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["code", "account"])
async def test_rejected_native_proof_cannot_resolve_expiry(history, tx, target):
    setattr(history, "rejected_" + target, True)
    history.head = history.birth + 20
    with pytest.raises(RuntimeError, match="proof_verification_failed"):
        await history.reader.expiry(expired(history, tx))


@pytest.mark.asyncio
async def test_expiry_verification_resumes_after_cancellation_in_old_ancestry(
    history, tx, monkeypatch
):
    journal = expired(history, tx)
    history.head = history.birth + 200
    arrived = asyncio.Event()
    release = asyncio.Event()
    request = history.rpc.request
    blocked = history.hashes[history.birth + 5]

    async def wait(method, params):
        if method == "chain_getHeader" and params == (blocked,):
            arrived.set()
            await release.wait()
        return await request(method, params)

    monkeypatch.setattr(history.rpc, "request", wait)
    task = asyncio.create_task(history.reader.expiry(journal))
    await asyncio.wait_for(arrived.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert history.reader._expiry_result is not None
    assert history.reader._cursor.snapshot.block_number == history.birth + 6
    reads, heads, executions = len(history.calls), history.heads, len(tx.case.executed)
    release.set()
    result = await history.reader.expiry(journal)
    assert result.nonce == journal.attempt.signing.nonce
    assert history.heads == heads and len(tx.case.executed) == executions
    assert len(history.calls) - reads == 6


@pytest.mark.asyncio
async def test_receipt_cache_does_not_substitute_for_expiry_account_proof(history, tx):
    await history.reader.find(history.journal)
    history.head = history.birth + 20
    history.rejected_account = True
    with pytest.raises(RuntimeError, match="proof_verification_failed"):
        await history.reader.expiry(expired(history, tx))


@pytest.mark.asyncio
async def test_descending_expiry_and_receipt_history_share_one_ancestry_walk(history):
    history.head = history.birth + 200
    later = journal_at(history, 40)
    observed = history.birth + 50
    block_hash = history.hashes[observed]
    later = evolve_journal(
        later,
        phase="expired_nonce_available",
        last_observed_block=observed,
        last_observed_block_hash=block_hash,
        expiry_observation=later.attempt.signing.model_copy(
            update={
                "block_number": observed,
                "block_hash": block_hash,
                "state_root": history.headers[block_hash]["stateRoot"],
            }
        ),
    )
    nonce = await history.reader.expiry(later)
    receipt = await history.reader.find(history.journal)
    assert nonce.snapshot.block_number == observed
    assert receipt.receipt.block_number == history.birth + 2
    assert nonce.owned_head == receipt.owned_head
    assert history.heads == 1
    headers = [params[0] for method, params in history.calls if method == "chain_getHeader"]
    assert len(headers) == len(set(headers)) == 201
    assert len(history.reader._era) == 8


@pytest.mark.asyncio
async def test_expiry_cannot_authenticate_changed_preflight_hash(history, tx):
    import hashlib

    journal = expired(history, tx)
    payload = journal.attempt.model_dump(mode="json", by_alias=True, exclude={"attempt_id"})
    payload["preflight_block_hash"] = "0x" + "ee" * 32
    payload["signing"]["block_hash"] = payload["preflight_block_hash"]
    payload["attempt_id"] = hashlib.sha256(
        journal.attempt._identity_domain + canonical_json_bytes(payload)
    ).hexdigest()
    journal = evolve_journal(journal, attempt=type(journal.attempt).model_validate(payload))
    history.head = history.birth + 20
    with pytest.raises(RegistrationBridgeError, match="preflight_ancestry_mismatch"):
        await history.reader.expiry(journal)
