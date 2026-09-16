from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from dataclasses import replace
from types import MethodType, SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_dispatch import DispatchFinalityProvider
from umi.finalized_ancestry import HeaderPathCache, encode_rpc_header, recover_header_path
from umi.protocol import canonical_json_bytes
from umi.validator_chain import FinalizedProofCollector
from umi.validator_plans import VerifiedFinalizedBlock

from .test_competition_chain import _Rpc
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_open_competition import policy as policy


def make_headers(first, last):
    headers, by_height = {}, {}
    parent = "0x" + "11" * 32
    for number in range(first, last + 1):
        value = {
            "parentHash": parent,
            "number": hex(number),
            "stateRoot": "0x" + hashlib.sha256(str(number).encode()).hexdigest(),
            "extrinsicsRoot": "0x" + "33" * 32,
            "digest": {"logs": ["0x00"]},
        }
        encoded = encode_rpc_header(value)
        block_hash = "0x" + hashlib.blake2b(bytes.fromhex(encoded[2:]), digest_size=32).hexdigest()
        headers[block_hash] = value
        by_height[number] = block_hash
        parent = block_hash
    return headers, by_height


def make_anchor(config, policy, headers, by_height):
    height = max(by_height)
    block_hash = by_height[height]
    header = headers[block_hash]
    raw = canonical_json_bytes(
        {
            "evidence_class": "verifier_attested_finality",
            "offline_finality_proof": False,
            "genesis_hash": "0x" + config.chain_pin.genesis_block_hash,
            "block": {"scale_header": encode_rpc_header(header)},
        }
    )
    from umi.open_competition import digest

    return VerifiedFinalizedBlock(
        height,
        block_hash,
        header["stateRoot"],
        1_800_000_000_000,
        digest(policy),
        config.chain_pin,
        config.finality_pin.release_sha256_by_target[config.target_triple],
        raw,
        hashlib.sha256(raw).hexdigest(),
    )


@pytest.fixture
def ancestry(chain_config, policy):
    first = chain_config.minimum_finalized_block + 10
    headers, by_height = make_headers(first, first + 4)
    anchor = make_anchor(chain_config, policy, headers, by_height)
    calls = []

    async def request(method, params):
        assert method == "chain_getHeader"
        calls.append(params[0])
        return headers[params[0]]

    return first, headers, by_height, anchor, request, calls


async def test_recovers_only_a_hash_linked_ancestor(ancestry):
    first, headers, by_height, anchor, request, calls = ancestry
    ref, path = await recover_header_path(anchor, first + 1, request)
    value = headers[by_height[first + 1]]
    assert ref == FinalizedSnapshotRef(
        first + 1, by_height[first + 1], value["parentHash"], value["stateRoot"]
    )
    assert len(path) == len(calls) == 3
    assert calls == [by_height[h] for h in range(first + 3, first, -1)]


async def test_cancelled_walk_retains_progress_and_rechecks_the_complete_path(ancestry):
    first, _, by_height, anchor, request, calls = ancestry
    cache = HeaderPathCache()
    waiting = asyncio.Event()

    async def interrupted(method, params):
        if params[0] == by_height[first + 1]:
            waiting.set()
            await asyncio.Future()
        return await request(method, params)

    task = asyncio.create_task(recover_header_path(anchor, first, interrupted, cache=cache))
    await asyncio.wait_for(waiting.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(calls) == len(cache._headers) == 2
    recovered, path = await recover_header_path(anchor, first, request, cache=cache)
    assert recovered.block_hash == by_height[first]
    assert len(path) == len(calls) == 4
    # Already downloaded headers were not requested again.
    assert calls == [by_height[h] for h in range(first + 3, first - 1, -1)]
    expected, uncached_path = await recover_header_path(anchor, first, request)
    assert (recovered, path) == (expected, uncached_path)


async def test_cached_header_never_replaces_anchor_hash_validation(ancestry):
    first, headers, by_height, anchor, request, _ = ancestry
    cache = HeaderPathCache()
    await recover_header_path(anchor, first, request, cache=cache)
    cache._headers[by_height[first + 3]] = encode_rpc_header(headers[by_height[first + 2]])
    with pytest.raises(ValueError, match="ancestry"):
        await recover_header_path(anchor, first, request, cache=cache)
    with pytest.raises(ValueError, match="anchor identity"):
        await recover_header_path(
            replace(anchor, block_hash="0x" + "ff" * 32), first, request, cache=cache
        )


async def test_cached_bytes_count_toward_path_limit(ancestry, monkeypatch):
    first, _, _, anchor, request, _ = ancestry
    cache = HeaderPathCache()
    await recover_header_path(anchor, first, request, cache=cache)
    monkeypatch.setattr("umi.finalized_ancestry.MAXIMUM_PATH_BYTES", 100)
    with pytest.raises(ValueError, match="path exceeds"):
        await recover_header_path(anchor, first, request, cache=cache)


def test_progress_cache_evicts_to_both_count_and_byte_bounds(ancestry, monkeypatch):
    _, headers, _, _, _, _ = ancestry
    cache = HeaderPathCache()
    monkeypatch.setattr("umi.finalized_ancestry.MAXIMUM_DISTANCE", 2)
    for key, header in headers.items():
        cache.remember(key, encode_rpc_header(header))
        assert len(cache._headers) <= 2
    last = next(reversed(headers))
    encoded = encode_rpc_header(headers[last])
    size = (len(encoded) - 2) // 2
    monkeypatch.setattr("umi.finalized_ancestry.MAXIMUM_PATH_BYTES", size)
    cache.remember(last, encoded)
    assert list(cache._headers) == [last]
    assert cache._bytes == size
    with pytest.raises(ValueError, match="hash mismatch"):
        cache.remember("0x" + "ff" * 32, encoded)


@pytest.mark.parametrize("field", ["parentHash", "stateRoot", "extrinsicsRoot", "number", "digest"])
async def test_rpc_mutation_cannot_change_committed_header(ancestry, field):
    first, headers, by_height, anchor, request, _ = ancestry
    bad = headers[by_height[first + 3]]
    bad[field] = (
        {"logs": []}
        if field == "digest"
        else (hex(first + 2) if field == "number" else "0x" + "ff" * 32)
    )
    with pytest.raises(ValueError, match="ancestry"):
        await recover_header_path(anchor, first + 1, request)


@pytest.mark.parametrize("distance", [0, -1, 2049, True])
async def test_recovery_distance_is_bounded(ancestry, distance):
    first, _, _, anchor, request, calls = ancestry
    with pytest.raises(ValueError):
        await recover_header_path(anchor, first, request, maximum_distance=distance)
    assert calls == []


async def test_too_old_future_and_noninteger_heights_never_query_rpc(ancestry):
    first, _, _, anchor, request, calls = ancestry
    for height in (first - 2049, anchor.height, anchor.height + 1, True, 1.5):
        with pytest.raises(ValueError):
            await recover_header_path(anchor, height, request)
    assert calls == []


async def test_anchor_identity_and_evidence_class_are_checked(ancestry):
    first, _, _, anchor, request, calls = ancestry
    with pytest.raises(ValueError, match="anchor identity"):
        await recover_header_path(replace(anchor, state_root="0x" + "aa" * 32), first, request)
    body = json.loads(anchor.finality_evidence)
    body["evidence_class"] = "rpc_claim"
    raw = canonical_json_bytes(body)
    bad = replace(
        anchor, finality_evidence=raw, finality_evidence_sha256=hashlib.sha256(raw).hexdigest()
    )
    with pytest.raises(ValueError, match="original observer"):
        await recover_header_path(bad, first, request)
    assert calls == []


@pytest.mark.parametrize("mutation", ["extra", "number", "hash", "logs", "empty_log", "large_log"])
def test_header_shape_is_bounded(ancestry, mutation):
    first, headers, by_height, *_ = ancestry
    value = copy.deepcopy(headers[by_height[first]])
    if mutation == "extra":
        value["arbitrary"] = 1
    elif mutation == "number":
        value["number"] = "0x20000000000000"
    elif mutation == "hash":
        value["parentHash"] = "0x01"
    elif mutation == "logs":
        value["digest"]["logs"] = ["0x00"] * 1025
    elif mutation == "empty_log":
        value["digest"]["logs"] = ["0x"]
    else:
        value["digest"]["logs"] = ["0x" + "00" * 65536]
    with pytest.raises(ValueError):
        encode_rpc_header(value)


async def test_path_byte_budget_is_enforced(ancestry, monkeypatch):
    first, _, _, anchor, request, _ = ancestry
    monkeypatch.setattr("umi.finalized_ancestry.MAXIMUM_PATH_BYTES", 100)
    with pytest.raises(ValueError, match="path exceeds"):
        await recover_header_path(anchor, first, request)


@pytest.fixture
def recovery(chain):
    first = chain.config.minimum_finalized_block + 10
    headers, by_height = make_headers(first, first + 4)
    anchor = replace(
        make_anchor(chain.config, chain.policy, headers, by_height),
        timestamp_ms=chain.clock.now - 1000,
    )
    anchor_header = headers[anchor.block_hash]
    ref = FinalizedSnapshotRef(
        anchor.height, anchor.block_hash, anchor_header["parentHash"], anchor.state_root
    )
    state = SimpleNamespace(bad_proof=False, bad_timestamp=False, roots=[], calls=[])

    class Finality:
        async def verified_finalized_snapshot(self):
            return ref

        async def verified_block_at(self, height):
            return anchor if height == anchor.height else None

        async def verified_block_after(self, height, *, maximum_distance):
            assert 0 < anchor.height - height <= maximum_distance
            return anchor

    class Rpc:
        async def request(self, method, params):
            state.calls.append(method)
            if method == "chain_getHeader":
                return headers[params[0]]
            if method == "chain_getBlockHash":
                return by_height[params[0]]
            requested_hash = params[-1]
            header = headers[requested_hash]
            number = int(header["number"], 16)
            snapshot = FinalizedSnapshotRef(
                number, requested_hash, header["parentHash"], header["stateRoot"]
            )
            timestamp = (
                True
                if state.bad_timestamp
                else anchor.timestamp_ms - (anchor.height - number) * 12_000
            )
            source = _Rpc(SimpleNamespace(ref=snapshot, timestamp=timestamp))
            source.bad_proof = state.bad_proof
            return await source.request(method, params)

    class Verifier:
        def __call__(self, **kwargs):
            raise AssertionError("timestamp verification must use a multiproof")

        def verify_many(self, **kwargs):
            state.roots.append(kwargs["state_root"])
            return kwargs["proof"] == (b"proof",)

    source = chain.provider
    source._owned = True
    source._ancestry_headers = HeaderPathCache()
    source._registration_rpc = Rpc()
    source._finality = Finality()
    source._proofs = FinalizedProofCollector(
        source._registration_rpc, finality=source._finality, verifier=Verifier()
    )
    source._startup_floor = anchor.height - 1
    source._recover_historical_block = MethodType(
        DispatchFinalityProvider._recover_historical_block, source
    )
    source._task = SimpleNamespace(done=lambda: False)
    return SimpleNamespace(
        source=source,
        first=first,
        state=state,
        anchor=anchor,
        headers=headers,
        by_height=by_height,
        chain=chain,
    )


async def test_dispatch_recovers_with_timestamp_proof_and_retains_derivation(recovery):
    source, height = recovery.source, recovery.first + 1
    head, (block,) = await DispatchFinalityProvider.verified_blocks(source, (height,))
    assert head == recovery.anchor and block.height == height
    assert block.block_hash == recovery.by_height[height]
    assert block.timestamp_ms == head.timestamp_ms - 36_000
    assert recovery.state.roots == [bytes.fromhex(block.state_root[2:])]
    evidence = json.loads(block.finality_evidence)
    assert evidence["evidence_class"] == "verified_finalized_ancestry"
    assert evidence["anchor_sha256"] == head.finality_evidence_sha256
    assert "accepted_at_unix_ms" not in evidence
    from contextlib import closing

    with closing(source._connect()) as db:
        rows = db.execute("SELECT body FROM artifacts").fetchall()
        assert rows == [(block.finality_evidence,)]
        assert db.execute("SELECT count(*) FROM captures").fetchone()[0] == 0
    assert await source._finality.verified_block_at(height) is None
    assert "chain_getFinalizedHead" not in recovery.state.calls
    _, (again,) = await DispatchFinalityProvider.verified_blocks(source, (height,))
    assert again == block
    assert recovery.state.calls.count("chain_getHeader") >= 3
    assert len(source._ancestry_headers._headers) == 3
    # Header reuse still performs a new timestamp storage proof.
    assert recovery.state.roots == [bytes.fromhex(block.state_root[2:])] * 2


@pytest.mark.parametrize("mutation", ["proof", "timestamp", "stale"])
async def test_warm_header_cache_does_not_waive_freshness_or_timestamp_proofs(recovery, mutation):
    source, height = recovery.source, recovery.first + 1
    await DispatchFinalityProvider.verified_blocks(source, (height,))
    assert source._ancestry_headers._headers
    if mutation == "proof":
        recovery.state.bad_proof = True
    elif mutation == "timestamp":
        recovery.state.bad_timestamp = True
    else:
        recovery.chain.clock.now += 120_001
    with pytest.raises((ValueError, RuntimeError)):
        await DispatchFinalityProvider.verified_blocks(source, (height,))


@pytest.mark.parametrize(
    "mutation", ["proof", "timestamp", "minimum", "unowned", "capacity", "stale"]
)
async def test_dispatch_recovery_never_waives_existing_guards(recovery, mutation):
    source, height = recovery.source, recovery.first + 1
    if mutation == "proof":
        recovery.state.bad_proof = True
    elif mutation == "timestamp":
        recovery.state.bad_timestamp = True
    elif mutation == "minimum":
        source.config = source.config.model_copy(update={"minimum_finalized_block": height + 1})
    elif mutation == "unowned":
        source._owned = False
    elif mutation == "capacity":
        source.config = source.config.model_copy(update={"maximum_cache_bytes": 1})
    else:
        recovery.chain.clock.now += 120_001
    with pytest.raises((ValueError, RuntimeError)):
        await DispatchFinalityProvider.verified_blocks(source, (height,))
    from contextlib import closing

    with closing(source._connect()) as db:
        assert db.execute("SELECT count(*) FROM artifacts").fetchone()[0] == 0


async def test_recovery_timeout_does_not_return_partial_evidence(recovery):
    async def stalled(*args):
        await asyncio.Event().wait()

    recovery.source._registration_rpc.request = stalled
    recovery.source.config = recovery.source.config.model_copy(
        update={"collection_timeout_seconds": 0.01}
    )
    with pytest.raises(asyncio.TimeoutError):
        await DispatchFinalityProvider.verified_blocks(recovery.source, (recovery.first,))
