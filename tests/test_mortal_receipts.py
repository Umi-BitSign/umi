"""General mortal receipt recovery through native readers and synthetic chain ports."""

import asyncio
import json

import pytest

from umi.mortal_receipts import MortalReceiptError, MortalReceiptQuery, MortalReceiptReader

from .test_bridge_receipt_provider import provider as provider
from .test_bridge_receipts import history as history
from .test_bridge_transactions import case as case
from .test_bridge_transactions import signed_policy as signed_policy
from .test_bridge_transactions import tx as tx


@pytest.fixture
def query(history):
    history.head = max(history.hashes)
    return MortalReceiptQuery(
        schema="umi-mortal-receipt-query/1",
        birth_block=history.birth,
        birth_hash=history.hashes[history.birth],
        mortality_period=128,
        signed_extrinsic=history.journal.signed_extrinsic,
    )


@pytest.mark.parametrize(
    "history,period",
    [({"distance": p + 5, "inclusion": p - 1}, p) for p in (4, 8, 128, 4096)],
    indirect=["history"],
)
async def test_owned_provider_recovers_last_live_block_for_each_supported_era(
    provider, history, query, period, tx
):
    query = query.model_copy(update={"mortality_period": period})
    result = await provider.read_mortal_receipt(query)
    assert result.successful
    assert result.receipt.block_number == history.birth + period - 1
    assert result.signed_extrinsic_hash == query.signed_extrinsic_hash
    assert result.owned_head.block_number == history.head
    assert tx.case.executed[-1] == f"wasm-at-{history.birth + period - 2}".encode()
    calls = len(history.calls)
    assert await provider.read_mortal_receipt(query) == result
    assert len(history.calls) == calls
    assert len(provider._bridge_receipts._era) == period
    assert provider.proof_captures == 1 and history.heads == 0


@pytest.mark.parametrize("history", [{"inclusion": 126}], indirect=True)
@pytest.mark.parametrize("successful", [True, False])
async def test_dispatch_result_rechecked_after_cold_start(history, query, tx, successful):
    block = history.birth + 126
    root = history.headers[history.hashes[block]]["stateRoot"]
    events = json.loads(history.values[root][b"System.Events"])
    events[1]["event_id"] = "ExtrinsicSuccess" if successful else "ExtrinsicFailed"
    history.values[root][b"System.Events"] = json.dumps(events).encode()

    def reader():
        return MortalReceiptReader(
            finality=history.finality,
            rpc=history.rpc,
            verifier=history.verifier,
            runtime_executor=tx.case.executor,
        )

    result = await reader().find(query)
    assert result.successful is successful and result.receipt.block_number == block
    count = len(history.calls)
    assert await reader().find(query) == result
    assert len(history.calls) > count and history.heads == 2


@pytest.mark.parametrize("history", [{"inclusion": n} for n in (0, 128, 129)], indirect=True)
async def test_birth_and_expired_blocks_do_not_supply_a_receipt(provider, history, query):
    assert await provider.read_mortal_receipt(query) is None
    fetched = [params[0] for method, params in history.calls if method == "chain_getBlock"]
    assert fetched == [history.hashes[n] for n in range(history.birth + 1, history.birth + 128)]


@pytest.mark.parametrize(
    "field,value",
    [
        ("birth_block", True),
        ("birth_block", "100"),
        ("birth_block", 100.0),
        ("birth_block", 0),
        ("birth_block", 2**53 - 1),
        ("birth_hash", "0x" + "ZZ" * 32),
        ("birth_hash", ("0x" + "11" * 32).encode()),
        ("mortality_period", True),
        ("mortality_period", "128"),
        ("mortality_period", 128.0),
        ("mortality_period", 3),
        ("mortality_period", 12),
        ("mortality_period", 8192),
        ("signed_extrinsic", ""),
        ("signed_extrinsic", "00" * (65536 + 1)),
        ("signed_extrinsic", "0x1234"),
        ("signed_extrinsic", b"1234"),
    ],
)
async def test_copied_query_is_revalidated_before_rpc(provider, history, query, field, value):
    with pytest.raises(ValueError):
        await provider.read_mortal_receipt(query.model_copy(update={field: value}))
    assert not history.calls and provider.proof_captures == 0


@pytest.mark.parametrize("history", [{"inclusion": 126}], indirect=True)
@pytest.mark.parametrize("proof", ["body", "code", "events"])
async def test_general_era_retains_native_proof_checks(provider, history, query, proof):
    setattr(history, "rejected_" + proof, True)
    with pytest.raises(RuntimeError, match=r"root_invalid|storage_proof_verification_failed"):
        await provider.read_mortal_receipt(query)
    assert provider._bridge_receipts._found is None


@pytest.mark.parametrize("history", [{"inclusion": 126}], indirect=True)
async def test_search_identity_includes_era_and_exact_bytes(provider, history, query):
    assert (
        await provider.read_mortal_receipt(query.model_copy(update={"mortality_period": 8})) is None
    )
    changed = query.model_copy(update={"signed_extrinsic": b"missing".hex()})
    assert await provider.read_mortal_receipt(changed) is None
    assert (await provider.read_mortal_receipt(query)).successful
    assert provider.proof_captures == 3
    with pytest.raises(MortalReceiptError, match="preflight_ancestry_mismatch"):
        await provider.read_mortal_receipt(
            query.model_copy(update={"birth_hash": "0x" + "ff" * 32})
        )
    assert provider.proof_captures == 4


@pytest.mark.parametrize("history", [{"inclusion": 126}], indirect=True)
async def test_general_result_cannot_expand_bridge_recovery_era(provider, history, query):
    before = history.journal.model_dump()
    assert (await provider.read_mortal_receipt(query)).successful
    assert await provider.read_bridge_receipt(history.journal) is None
    assert history.journal.model_dump() == before
    assert len(provider._bridge_receipts._era) == 8


@pytest.mark.parametrize("value", [None, {}, "not a query"])
async def test_wrong_query_type_rejected_before_rpc(provider, history, value):
    with pytest.raises(ValueError, match="query type"):
        await provider.read_mortal_receipt(value)
    assert not history.calls and provider.proof_captures == 0


@pytest.mark.parametrize("history", [{"inclusion": 126, "distance": 4200}], indirect=True)
async def test_long_outage_resumes_cancelled_walk_with_bounded_era(provider, history, query):
    request, entered = history.rpc.request, asyncio.Event()
    paused = history.hashes[history.birth + 3000]

    async def interrupted(method, params):
        if method == "chain_getHeader" and params == (paused,):
            entered.set()
            await asyncio.Future()
        return await request(method, params)

    history.rpc.request = interrupted
    task = asyncio.create_task(provider.read_mortal_receipt(query))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    reader = provider._bridge_receipts
    assert reader._cursor.snapshot.block_number == history.birth + 3001
    assert not provider._lock.locked() and not reader._lock.locked()
    history.rpc.request = request
    before = len(history.calls)
    assert (await provider.read_mortal_receipt(query)).receipt.block_number == history.birth + 126
    assert history.calls[before] == ("chain_getHeader", (paused,))
    assert provider.proof_captures == 1 and len(reader._era) == 128


async def test_general_reader_shares_provider_shutdown_and_ownership_guards(
    provider, history, query
):
    provider._owned = False
    with pytest.raises(ValueError, match="observer"):
        await provider.read_mortal_receipt(query)
    provider._owned = True
    await provider.aclose()
    with pytest.raises(ValueError, match="closed"):
        await provider.read_mortal_receipt(query)
    assert history.calls == []
