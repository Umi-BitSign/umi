from __future__ import annotations

import asyncio

import pytest

from umi.proof_rpc_cache import BlockPinnedRpcCache
from umi.validator_chain import ValidatorChainError

from .test_competition_chain import chain_config as chain_config
from .test_competition_chain import policy as policy
from .test_validator_chain import FakeFinality, _collector, _hash, _rpc


async def test_identical_concurrent_reads_share_one_call_and_return_independent_values():
    started, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def fetch(method, params):
        calls.append((method, params))
        started.set()
        await release.wait()
        return {"proof": ["original"]}

    cache = BlockPinnedRpcCache(fetch)
    tasks = [
        asyncio.create_task(cache.request("state_getReadProof", (["0x01"], _hash(1))))
        for _ in range(20)
    ]
    await started.wait()
    release.set()
    values = await asyncio.gather(*tasks)
    values[0]["proof"].append("changed")
    assert values[1] == {"proof": ["original"]}
    assert await cache.request("state_getReadProof", (["0x01"], _hash(1))) == values[1]
    assert len(calls) == 1
    assert cache.shared_reads == 19 and cache.hits == 1


@pytest.mark.parametrize(
    "method,params",
    [
        ("chain_getHeader", ()),
        ("chain_getHeader", ("latest",)),
        ("chain_getBlockHash", (42,)),
        ("chain_getFinalizedHead", ()),
        ("state_getStorageAt", ("0x01",)),
    ],
)
async def test_current_and_number_only_reads_are_never_cached(method, params):
    calls = []

    async def fetch(method, params):
        calls.append((method, params))
        return len(calls)

    cache = BlockPinnedRpcCache(fetch)
    assert await cache.request(method, params) == 1
    assert await cache.request(method, params) == 2
    assert not cache.entries


async def test_hash_and_storage_keys_are_separate_and_retention_is_bounded():
    calls, clock = [], [0.0]

    async def fetch(method, params):
        calls.append((method, params))
        return len(calls)

    cache = BlockPinnedRpcCache(fetch, maximum_entries=2, monotonic=lambda: clock[0])
    assert await cache.request("state_getStorageAt", ("0x01", _hash(1))) == 1
    assert await cache.request("state_getStorageAt", ("0x02", _hash(1))) == 2
    assert await cache.request("state_getStorageAt", ("0x01", _hash(2))) == 3
    assert await cache.request("state_getStorageAt", ("0x01", _hash(1))) == 4
    clock[0] = 31
    assert await cache.request("state_getStorageAt", ("0x01", _hash(1))) == 5
    assert len(cache.entries) <= 2


async def test_failure_and_missing_block_are_not_cached():
    calls = 0

    async def fetch(method, params):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValidatorChainError("proof_rpc_rate_limited")
        return None if calls == 2 else {"number": "0x2a"}

    cache = BlockPinnedRpcCache(fetch)
    with pytest.raises(ValidatorChainError, match="proof_rpc_rate_limited"):
        await cache.request("chain_getHeader", (_hash(1),))
    assert await cache.request("chain_getHeader", (_hash(1),)) is None
    assert await cache.request("chain_getHeader", (_hash(1),)) == {"number": "0x2a"}
    assert calls == 3


async def test_cancelled_caller_does_not_cancel_shared_read_and_shutdown_drains():
    started, release = asyncio.Event(), asyncio.Event()

    async def fetch(method, params):
        started.set()
        await release.wait()
        return {"number": "0x2a"}

    cache = BlockPinnedRpcCache(fetch)
    first = asyncio.create_task(cache.request("chain_getHeader", (_hash(1),)))
    await started.wait()
    second = asyncio.create_task(cache.request("chain_getHeader", (_hash(1),)))
    await asyncio.sleep(0)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    closing = asyncio.create_task(cache.aclose())
    await asyncio.sleep(0)
    assert not closing.done()
    release.set()
    assert await second == {"number": "0x2a"}
    await closing
    assert cache.network_reads == 1 and not cache.entries and cache.bytes == 0
    with pytest.raises(ValueError, match="closed"):
        await cache.request("chain_getHeader", (_hash(1),))


async def test_oversized_results_are_not_retained():
    calls = 0

    async def fetch(method, params):
        nonlocal calls
        calls += 1
        return "x" * 200

    cache = BlockPinnedRpcCache(fetch, maximum_bytes=100)
    for _ in range(2):
        assert await cache.request("state_getMetadata", (_hash(1),)) == "x" * 200
    assert calls == 2 and not cache.entries and cache.bytes == 0


async def test_distinct_reads_wait_for_capacity_and_cancelled_read_releases_it():
    started, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def fetch(method, params):
        calls.append(params)
        started.set()
        await release.wait()
        return {"hash": params[0]}

    cache = BlockPinnedRpcCache(fetch, maximum_inflight=1)
    first = asyncio.create_task(cache.request("chain_getHeader", (_hash(1),)))
    await started.wait()
    second = asyncio.create_task(cache.request("chain_getHeader", (_hash(2),)))
    await asyncio.sleep(0)
    assert calls == [[_hash(1)]] and not second.done()
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    release.set()
    assert await second == {"hash": _hash(2)}
    assert calls == [[_hash(1)], [_hash(2)]]
    assert not cache.inflight and not cache.waiters
    await cache.aclose()


async def test_repeated_native_head_checks_reuse_only_verified_snapshot():
    rpc, finality = _rpc(), FakeFinality()
    collector = _collector(rpc, verifier=lambda **_: True, finality=finality)
    heads = await asyncio.gather(*(collector.finalized_snapshot() for _ in range(20)))
    assert heads == [finality.snapshot] * 20
    assert finality.calls == 20
    assert [method for method, _ in rpc.calls] == ["chain_getHeader", "chain_getBlockHash"]

    # An unavailable owned verifier must still fail despite the header cache.
    async def unavailable():
        raise RuntimeError("observer stopped")

    finality.verified_finalized_snapshot = unavailable
    with pytest.raises(ValidatorChainError, match="owned_finality_unavailable"):
        await collector.finalized_snapshot()


async def test_changed_owned_root_and_failed_crosscheck_cannot_use_snapshot_cache():
    from dataclasses import replace

    rpc, finality = _rpc(), FakeFinality()
    collector = _collector(rpc, verifier=lambda **_: True, finality=finality)
    await collector.finalized_snapshot()
    finality.snapshot = replace(finality.snapshot, state_root=_hash(9))
    with pytest.raises(ValidatorChainError, match="finalized_state_root_mismatch"):
        await collector.finalized_snapshot()
    rpc.responses["chain_getHeader"]["stateRoot"] = _hash(9)
    assert await collector.finalized_snapshot() == finality.snapshot
    assert len(rpc.calls) == 6


async def test_cached_storage_bytes_still_require_native_proof_verification():
    rpc, verified = _rpc(), [True]
    cache = BlockPinnedRpcCache(rpc.request)
    verifier_calls = []

    def verifier(**kwargs):
        verifier_calls.append(kwargs)
        return verified[0]

    collector = _collector(cache, verifier=verifier)
    snapshot = await collector.finalized_snapshot()
    assert (await collector.storage_evidence(snapshot, b"\x12key")).value == b"value"
    assert (await collector.storage_evidence(snapshot, b"\x12key")).value == b"value"
    verified[0] = False
    with pytest.raises(ValidatorChainError):
        await collector.storage_evidence(snapshot, b"\x12key")
    assert len(verifier_calls) == 3
    assert [m for m, _ in rpc.calls].count("state_getReadProof") == 1
    assert [m for m, _ in rpc.calls].count("state_getStorageAt") == 1


async def test_registration_bulk_transport_reuses_exact_block_read(chain_config, monkeypatch):
    from umi import competition_chain

    calls = []

    class Wire:
        def __init__(self, *args, **kwargs):
            pass

        async def request(self, method, params):
            calls.append((method, params))
            return [{"block": params[1], "changes": [[k, "0x01"] for k in params[0]]}]

    monkeypatch.setattr(competition_chain, "BittensorRawJsonRpc", Wire)
    rpc = competition_chain._RegistrationRpc(chain_config, bulk_storage_reads=True)
    first = await rpc.storage_values(_hash(1), (b"key",))
    first["0x6b6579", _hash(1)] = "changed"
    second = await rpc.storage_values(_hash(1), (b"key",))
    assert second == {("0x6b6579", _hash(1)): "0x01"}
    assert len(calls) == 1
    await rpc.storage_values(_hash(2), (b"key",))
    assert len(calls) == 2
    await rpc.aclose()
