"""Native request recovery with synthetic RPC/trie-verifier boundaries."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace

import pytest

from umi.competition_chain import OwnedFinalityStale
from umi.competition_historical_blocks import HistoricalRequestBlocks
from umi.competition_transport_finality import CompetitionTransportFinality
from umi.policy import scoring_policy_hash

from .cohort_native_service_fixture import transport_policy
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_finalized_ancestry import recovery as recovery
from .test_open_competition import policy as policy


@pytest.fixture
def request_blocks(recovery):
    r = recovery
    transport = transport_policy()
    r.transport = transport.model_copy(
        update={
            "implementation_pins": transport.implementation_pins.model_copy(
                update={
                    "live_chain": r.source.config.chain_pin,
                    "finality_verifier": r.source.config.finality_pin,
                }
            )
        }
    )

    async def after(height, *, maximum_distance):
        assert maximum_distance is None
        assert height < r.anchor.height
        return r.anchor

    r.source._finality.verified_block_after = after
    r.view = CompetitionTransportFinality(r.source, r.transport)
    return r


async def test_transport_recovers_original_request_block_without_fresh_capture(request_blocks):
    r = request_blocks
    r.chain.clock.now += 10 * 60 * 60 * 1000
    height = r.first + 1
    block = await r.view.verified_block_at(height)
    assert block.height == height and block.block_hash == r.by_height[height]
    assert block.timestamp_ms == r.anchor.timestamp_ms - 36_000
    assert block.scoring_policy_hash == scoring_policy_hash(r.transport)
    assert r.state.roots == [bytes.fromhex(block.state_root[2:])]
    evidence = json.loads(block.finality_evidence)
    assert evidence["evidence_class"] == "verified_finalized_ancestry"
    assert evidence["anchor_sha256"] == r.anchor.finality_evidence_sha256
    assert evidence["offline_finality_proof"] is False
    assert await r.source._finality.verified_block_at(height) is None
    with r.source._connect() as db:
        assert db.execute("SELECT count(*) FROM captures").fetchone()[0] == 0
    with pytest.raises(OwnedFinalityStale):
        await r.view.finalized_head_height()


async def test_window_head_uses_fresh_owned_finality_without_membership_rpc(request_blocks):
    r = request_blocks
    async with r.source._lock:
        assert await asyncio.wait_for(r.view.finalized_head_height(), 30) == r.anchor.height
    assert r.state.calls == [] and r.state.roots == []
    r.source._task = None
    with pytest.raises(ValueError, match="observer is not running"):
        await r.view.finalized_head_height()
    assert r.state.calls == []


async def test_recovery_reuses_proofs_across_concurrent_short_lived_views(request_blocks):
    r = request_blocks
    async with r.source._lock:
        blocks = await asyncio.wait_for(
            asyncio.gather(
                *(
                    CompetitionTransportFinality(r.source, r.transport).verified_block_at(r.first)
                    for _ in range(10)
                )
            ),
            timeout=30,
        )
    assert all(block == blocks[0] for block in blocks)
    assert len(r.state.roots) == 1
    calls = list(r.state.calls)
    assert await r.view.verified_block_at(r.first) == blocks[0]
    assert r.state.calls == calls
    assert len(r.source._historical_request_blocks._locks) == 0


@pytest.mark.parametrize("damage", ["proof", "timestamp", "header", "anchor", "runtime"])
async def test_missing_header_recovery_never_waives_independent_proof(request_blocks, damage):
    r = request_blocks
    if damage == "proof":
        r.state.bad_proof = True
    elif damage == "timestamp":
        r.state.bad_timestamp = True
    elif damage == "header":
        r.headers[r.by_height[r.first + 3]]["stateRoot"] = "0x" + "ff" * 32
    elif damage == "anchor":
        r.anchor = replace(r.anchor, scoring_policy_hash="ff" * 32)
    else:
        r.source._runtime_pin = replace(r.source._runtime_pin, metadata_sha256="ff" * 32)
    with pytest.raises((ValueError, RuntimeError)):
        await r.view.verified_block_at(r.first)
    assert not r.source._historical_request_blocks._blocks
    assert await r.source._finality.verified_block_at(r.first) is None


async def test_failed_timestamp_proof_retries_using_retained_headers(request_blocks):
    r = request_blocks
    r.state.bad_proof = True
    with pytest.raises((ValueError, RuntimeError)):
        await r.view.verified_block_at(r.first)
    headers = r.state.calls.count("chain_getHeader")
    r.state.bad_proof = False
    assert (await r.view.verified_block_at(r.first)).height == r.first
    assert r.state.calls.count("chain_getHeader") == headers


async def test_restart_reanchors_durable_hints_without_header_refetch(request_blocks):
    r = request_blocks
    block = await r.view.verified_block_at(r.first)
    headers = r.state.calls.count("chain_getHeader")
    roots = len(r.state.roots)
    r.source._historical_request_blocks = HistoricalRequestBlocks(r.source)
    assert await r.view.verified_block_at(r.first) == block
    assert r.state.calls.count("chain_getHeader") == headers
    assert len(r.state.roots) == roots + 1


async def test_unowned_or_absent_anchor_stays_pending_without_rpc(request_blocks):
    r = request_blocks
    r.source._owned = False
    assert await r.view.verified_block_at(r.first) is None
    r.source._owned = True

    async def absent(*args, **kwargs):
        return None

    r.source._finality.verified_block_after = absent
    assert await r.view.verified_block_at(r.first) is None
    assert r.state.calls == []


async def test_cancelled_recovery_reuses_completed_headers_on_retry(request_blocks):
    r = request_blocks
    request = r.source._registration_rpc.request
    entered = asyncio.Event()

    async def interrupted(method, params):
        if method == "chain_getHeader" and params[0] == r.by_height[r.first]:
            entered.set()
            await asyncio.Future()
        return await request(method, params)

    r.source._registration_rpc.request = interrupted
    task = asyncio.create_task(r.view.verified_block_at(r.first))
    await asyncio.wait_for(entered.wait(), 30)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not r.source._historical_request_blocks._blocks
    r.source._registration_rpc.request = request
    assert (await r.view.verified_block_at(r.first)).height == r.first
    assert r.state.calls.count("chain_getHeader") == 4


async def test_verified_request_cache_eviction_is_bounded_and_recoverable(
    request_blocks, monkeypatch
):
    r = request_blocks
    monkeypatch.setattr("umi.competition_historical_blocks.MAXIMUM_REQUEST_BLOCK_CACHE_BYTES", 1)
    first = await r.view.verified_block_at(r.first)
    assert r.source._historical_request_blocks._bytes == 0
    assert not r.source._historical_request_blocks._blocks
    assert await r.view.verified_block_at(r.first) == first


async def test_original_window_recovered_from_owned_history_keeps_exact_request(request_blocks):
    from types import SimpleNamespace

    from umi.competition_cohort_request_window import capture_request_window
    from umi.competition_cohort_service_review import _same_window_facts
    from umi.protocol import canonical_json_bytes

    from .factories import challenge_request
    from .test_finalized_ancestry import make_anchor

    r = request_blocks
    transport = r.transport.model_copy(update={"activation_block": r.first})
    issued = r.first + 80

    class OriginalOwner:
        async def finalized_head_height(self):
            return r.anchor.height

        async def verified_block_at(self, height):
            owner = make_anchor(
                r.source.config,
                r.source.policy,
                r.headers,
                {n: h for n, h in r.by_height.items() if n <= height},
            )
            return replace(
                owner,
                timestamp_ms=r.anchor.timestamp_ms - (r.anchor.height - height) * 12_000,
                scoring_policy_hash=scoring_policy_hash(transport),
            )

    original = await capture_request_window(transport, OriginalOwner(), issued)
    template = challenge_request()
    video = template.video
    case = SimpleNamespace(video_sha256=video.sha256, stratum="continuous")
    request = original.request_with_ids(
        case, video, (template.batch_id, template.challenge_id), transport
    )
    before = canonical_json_bytes(request)
    independent = await capture_request_window(
        transport, CompetitionTransportFinality(r.source, transport), issued
    )
    _same_window_facts(independent, original)
    independent.check(request, transport)
    assert independent.schedule(transport) == original.schedule(transport)
    assert canonical_json_bytes(request) == before
    assert (
        independent.issuance.finality_evidence_sha256 != original.issuance.finality_evidence_sha256
    )
    assert await r.source._finality.verified_block_at(issued) is None
