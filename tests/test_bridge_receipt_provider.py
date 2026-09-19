"""Synthetic owned-provider lifecycle tests, without native binaries or RPC."""

from __future__ import annotations

import asyncio
import json
import threading
from types import SimpleNamespace

import pytest

from tests.test_bridge_expiry import expired
from tests.test_bridge_receipts import history as history
from tests.test_bridge_transactions import case as case
from tests.test_bridge_transactions import idle
from tests.test_bridge_transactions import signed_policy as signed_policy
from tests.test_bridge_transactions import tx as tx
from umi import competition_chain_state as chain_state
from umi.bridge.receipts import BridgeReceiptReader, VerifiedBridgeExpiry, VerifiedBridgeReceipt
from umi.bridge.transactions import evolve_journal
from umi.chain_evidence import FinalizedSnapshotRef
from umi.protocol import canonical_json_bytes


@pytest.fixture
async def provider(history, tx, monkeypatch):
    # Explicit unit-test ports. Production construction owns the sidecar,
    # native verifier and runtime executor under its validated configuration.
    item = object.__new__(chain_state.FinalizedCompetitionWeightProvider)
    item._lock = asyncio.Lock()
    item._stop = asyncio.Event()
    item._task = asyncio.create_task(item._stop.wait())
    finality_task = item._task
    item._close_task = None
    item._closed = False
    item._owned = True
    item._latest = None
    item._registration_rpc = None
    item._runtime_rpc = None
    item._cache_lease = None
    item._bridge_receipts = None
    item._weight_rpc = history.rpc
    item._runtime_executor = tx.case.executor
    item.config = SimpleNamespace(
        minimum_finalized_block=history.birth,
        proof_binary="/synthetic/proof-verifier",
        proof_binary_sha256="aa" * 32,
        collection_timeout_seconds=60,
    )
    item.proof_captures = 0
    item.rpc_closed = False

    async def capture():
        item.proof_captures += 1
        block_hash = history.hashes[history.head]
        raw = history.headers[block_hash]
        return FinalizedSnapshotRef(history.head, block_hash, raw["parentHash"], raw["stateRoot"])

    async def close_rpc():
        item.rpc_closed = True

    def verifier(**kwargs):
        assert kwargs == {
            "binary_path": item.config.proof_binary,
            "expected_sha256": item.config.proof_binary_sha256,
        }
        return history.verifier

    item._proofs = SimpleNamespace(finalized_snapshot=capture)
    monkeypatch.setattr(history.rpc, "aclose", close_rpc, raising=False)
    monkeypatch.setattr(chain_state, "SubprocessStorageProofVerifier", verifier)
    try:
        yield item
    finally:
        item._stop.set()
        await item.aclose()
        await finality_task


@pytest.mark.asyncio
async def test_provider_collects_receipt_with_its_owned_ports_and_reuses_reader(provider, history):
    before = canonical_json_bytes(history.journal)
    first = await provider.read_bridge_receipt(history.journal)
    assert first.successful
    assert first.receipt.block_number == history.birth + 2
    assert provider.proof_captures == 1
    assert history.heads == 0  # Uses the provider's owner, not an alternate finality port.
    calls = len(history.calls)
    reader = provider._bridge_receipts
    assert await provider.read_bridge_receipt(history.journal) == first
    assert provider._bridge_receipts is reader and len(history.calls) == calls
    assert canonical_json_bytes(history.journal) == before
    await provider.aclose()
    assert provider._bridge_receipts is None and provider.rpc_closed
    with pytest.raises(ValueError, match="closed"):
        await provider.read_bridge_receipt(history.journal)


@pytest.mark.asyncio
async def test_provider_owns_historical_expiry_reader_and_drains_before_close(
    provider, history, tx
):
    history.head = history.birth + 20
    journal = expired(history, tx)
    before = canonical_json_bytes(journal)
    result = await provider.read_bridge_expiry(journal)
    assert result.snapshot.block_number == history.birth + 10
    assert result.nonce == journal.attempt.signing.nonce
    assert provider.proof_captures == 1 and history.heads == 0
    assert canonical_json_bytes(journal) == before
    await provider.aclose()
    assert provider.rpc_closed and provider._bridge_receipts is None
    with pytest.raises(ValueError, match="closed"):
        await provider.read_bridge_expiry(journal)


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["owner", "task", "runtime", "rpc", "floor"])
async def test_provider_requires_owned_tools_and_finality_floor(provider, history, missing):
    if missing == "owner":
        provider._owned = False
    elif missing == "task":
        provider._task = None
    elif missing == "runtime":
        provider._runtime_executor = None
    elif missing == "rpc":
        provider._weight_rpc = None
    else:
        provider.config.minimum_finalized_block = history.head + 1
    with pytest.raises(ValueError, match=r"owned|observer"):
        await provider.read_bridge_receipt(history.journal)
    assert not history.calls


@pytest.mark.asyncio
async def test_provider_does_not_apply_exact_byte_recovery_to_legacy_journals(provider, tx):
    with pytest.raises(ValueError, match="version-2"):
        await provider.read_bridge_receipt(idle(tx.case.obs))
    assert provider._bridge_receipts is None


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["receipt", "expiry", "outcome_receipt", "outcome_expiry"])
async def test_provider_close_waits_for_cancelled_receipt_native_work(
    provider, history, tx, monkeypatch, operation
):
    entered, release = threading.Event(), threading.Event()
    if operation in {"receipt", "outcome_receipt"}:
        verify = history.verifier.verify_extrinsics_root

        def blocked(**kwargs):
            entered.set()
            assert release.wait(10)
            return verify(**kwargs)

        monkeypatch.setattr(history.verifier, "verify_extrinsics_root", blocked)
        journal = history.journal
        capture = provider.read_bridge_receipt
    else:
        verifier = type(history.verifier)
        verify = verifier.__call__

        def blocked(self, **kwargs):
            if kwargs["storage_key"] == b"System.Account":
                entered.set()
                assert release.wait(10)
            return verify(self, **kwargs)

        monkeypatch.setattr(verifier, "__call__", blocked)
        history.head = history.birth + 20
        journal = expired(history, tx)
        capture = provider.read_bridge_expiry
    if operation.startswith("outcome_"):
        capture = provider.read_bridge_outcome
    read = asyncio.create_task(capture(journal))
    close = None
    queued = None
    try:
        for _ in range(1000):
            if entered.is_set():
                break
            await asyncio.sleep(0.001)
        assert entered.is_set()
        read.cancel()
        await asyncio.sleep(0.01)
        read.cancel()
        queued = asyncio.create_task(capture(journal))
        close = asyncio.create_task(provider.aclose())
        await asyncio.sleep(0.01)
        assert not read.done() and not close.done() and not queued.done()
        assert provider._lock.locked() and not provider.rpc_closed
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await read
        if close is not None:
            await close
        if queued is not None:
            with pytest.raises(ValueError, match="closed"):
                await queued
    assert provider.rpc_closed and provider._bridge_receipts is None
    assert not provider._lock.locked()


@pytest.mark.parametrize("successful", [True, False])
async def test_outcome_uses_proven_dispatch_status(provider, history, successful):
    root = history.headers[history.hashes[history.birth + 2]]["stateRoot"]
    events = json.loads(history.values[root][b"System.Events"])
    events[1]["event_id"] = "ExtrinsicSuccess" if successful else "ExtrinsicFailed"
    history.values[root][b"System.Events"] = json.dumps(events).encode()
    result = await provider.read_bridge_outcome(history.journal)
    assert type(result) is VerifiedBridgeReceipt
    assert result.successful is successful
    assert result.receipt.block_number == history.birth + 2


async def test_outcome_proves_expiry_without_receipt_for_preparing(provider, history, tx):
    history.head = history.birth + 20
    result = await provider.read_bridge_outcome(tx.preparing)
    assert type(result) is VerifiedBridgeExpiry
    assert result.nonce == tx.preparing.attempt.signing.nonce
    assert result.snapshot.block_number == history.head
    assert not any(method == "chain_getBlock" for method, _ in history.calls)


@pytest.mark.parametrize("phase", ["receipt_returned", "applied", "failed"])
async def test_missing_recorded_receipt_never_falls_back_to_expiry(
    provider, history, monkeypatch, phase
):
    receipt = await provider.read_bridge_receipt(history.journal)
    journal = evolve_journal(
        history.journal,
        phase=phase,
        last_observed_block=receipt.receipt.block_number,
        last_observed_block_hash=receipt.receipt.block_hash,
        **{"failed_call" if phase == "failed" else "weight_call": receipt.receipt},
    )

    async def missing(reader, value):
        assert value == journal
        return None

    async def forbidden(*args):
        pytest.fail("recorded dispatch was replaced by expiry")

    monkeypatch.setattr(BridgeReceiptReader, "find", missing)
    monkeypatch.setattr(BridgeReceiptReader, "expiry", forbidden)
    with pytest.raises(ValueError, match="recorded bridge receipt"):
        await provider.read_bridge_outcome(journal)


@pytest.mark.parametrize("progress", [False, True])
async def test_outcome_retries_timeout_only_after_reader_progress(
    provider, history, monkeypatch, progress
):
    find = BridgeReceiptReader.find
    calls = 0

    async def interrupted(reader, journal):
        nonlocal calls
        calls += 1
        if calls == 1:
            if progress:
                # Actual authenticated work advances the reader, then the
                # transport loses its response. No fake progress marker.
                await find(reader, journal)
            raise asyncio.TimeoutError("injected lost response")
        return await find(reader, journal)

    monkeypatch.setattr(BridgeReceiptReader, "find", interrupted)
    if progress:
        result = await provider.read_bridge_outcome(history.journal)
        assert result.successful and calls == 2
    else:
        with pytest.raises(asyncio.TimeoutError, match="lost response"):
            await provider.read_bridge_outcome(history.journal)
        assert calls == 1
    assert not provider._lock.locked()
