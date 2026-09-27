"""Historical slot capture through native consumers and synthetic trie/RPC ports."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from umi.competition_reward_control import validate_owned_reward_control
from umi.competition_reward_control_archive import _Archive
from umi.historical_header_recovery import HistoricalHeaderRecoveryPending
from umi.open_competition import digest
from umi.validator_chain import ValidatorChainError

from .test_competition_reward_control_archive import (
    _linked_history,
    check,
)
from .test_competition_reward_control_archive import (
    chain as chain,
)
from .test_competition_reward_control_archive import (
    chain_config as chain_config,
)
from .test_competition_reward_control_archive import (
    control as control,
)
from .test_competition_reward_control_archive import (
    historical as historical,
)
from .test_competition_reward_control_archive import (
    policy as policy,
)
from .test_competition_reward_control_archive import (
    series_case as series_case,
)
from .test_finalized_ancestry import make_headers


async def capture_source(h, monkeypatch, distance=5):
    w = await _linked_history(h, monkeypatch, distance)
    archive = _Archive(w.raw, w.metadata)
    expected_items = tuple(
        (bytes.fromhex(c["key"][2:]), None if c["value"] is None else bytes.fromhex(c["value"][2:]))
        for c in json.loads(w.raw)["claims"]
    )
    monkeypatch.setattr(
        h.item.verifier,
        "verify_many",
        lambda **kw: (
            kw["state_root"] == bytes.fromhex(w.original.state_root[2:])
            and kw["items"] == expected_items
            and kw["proof"] == (b"proof",)
        ),
    )

    def read_many(*, state_root, storage_keys, proof, **limits):
        if state_root != bytes.fromhex(w.original.state_root[2:]) or proof != (b"proof",):
            raise ValueError("invalid synthetic historical proof")
        return tuple(
            (
                key,
                None
                if archive.values["0x" + key.hex()] is None
                else bytes.fromhex(archive.values["0x" + key.hex()][2:]),
            )
            for key in storage_keys
        )

    monkeypatch.setattr(h.item.verifier, "read_many", read_many)
    original_request = h.item.rpc.request
    calls = []

    async def request(method, params):
        calls.append((method, tuple(params)))
        if method == "chain_getBlockHash" and params[0] in w.heights:
            return w.heights[params[0]]
        if method == "chain_getHeader" and params[0] in w.headers:
            return w.headers[params[0]]
        if params[-1] == w.original.block_hash:
            return await archive.request(method, params)
        return await original_request(method, params)

    async def close():
        pass

    monkeypatch.setattr(h.item.rpc, "request", request)

    def own(provider):
        w.owned(provider)
        provider._registration_rpc = SimpleNamespace(request=request, aclose=close)
        return provider

    own(h.item.provider)
    return SimpleNamespace(w=w, archive=archive, calls=calls, own=own, request=request, close=close)


async def test_capture_without_retained_archive_and_replay_without_historical_rpc(
    historical, monkeypatch
):
    h = historical
    source = await capture_source(h, monkeypatch)
    result = await h.item.provider.capture_control_at(h.item.hotkey, h.old.height)
    check(h, result)
    assert result.control_sha256 == digest(h.c.genesis.decision)
    assert result.committed_at_block == 160
    assert result.snapshot.block_number == h.old.height
    assert h.blocks.get(h.old.height) is None
    body = json.loads(result.evidence)
    assert body["schema"] == "umi-historical-reward-control-observation/1"
    assert body["finality"]["evidence_class"] == "owned_finalized_ancestry"
    assert not body["chain_submission_authorized"]
    with pytest.raises(ValueError):
        validate_owned_reward_control(
            result,
            expected_control_hotkey=h.item.hotkey,
            expected_chain_config_sha256=digest(h.item.config),
        )
    assert any(m == "state_getReadProof" for m, _ in source.calls)
    assert not any(m.startswith("author_") for m, _ in source.calls)
    await h.item.provider.aclose()
    h.item.provider = source.own(h.reopen())

    async def head_only(method, params):
        assert method in {"chain_getHeader", "chain_getBlockHash"}
        assert params[0] in {source.w.head.block_hash, source.w.head.height}
        return await source.request(method, params)

    monkeypatch.setattr(h.item.rpc, "request", head_only)
    h.item.provider._registration_rpc = SimpleNamespace(request=head_only, aclose=source.close)
    replayed = await h.item.provider.review_control(result.evidence, result.metadata)
    check(h, replayed)
    assert replayed == result
    # Durable hints must not manufacture entries in the owned observer history.
    assert h.blocks.get(h.old.height) is None


async def test_capture_resumes_after_long_outage_and_provider_restart(historical, monkeypatch):
    h = historical
    source = await capture_source(h, monkeypatch, distance=2050)
    with pytest.raises(HistoricalHeaderRecoveryPending):
        await h.item.provider.capture_control_at(h.item.hotkey, h.old.height)
    assert not any(m.startswith("state_") for m, _ in source.calls)
    await h.item.provider.aclose()
    h.item.provider = source.own(h.reopen())
    for _ in range(20):
        try:
            result = await h.item.provider.capture_control_at(h.item.hotkey, h.old.height)
            break
        except HistoricalHeaderRecoveryPending:
            pass
    else:
        pytest.fail("capture did not converge after restart")
    check(h, result)
    assert result.snapshot.block_number == h.old.height
    assert h.item.clock.now - source.w.original.timestamp_ms > 9 * 60 * 60 * 1000


@pytest.mark.parametrize("height", [True, -1, 0, 2**53])
async def test_bad_capture_height_is_rejected_before_rpc(historical, monkeypatch, height):
    h = historical
    source = await capture_source(h, monkeypatch)
    with pytest.raises(ValueError):
        await h.item.provider.capture_control_at(h.item.hotkey, height)
    assert source.calls == []


@pytest.mark.parametrize("mutation", ["hash", "number", "parent", "proof", "value", "future"])
async def test_untrusted_history_is_rejected(historical, monkeypatch, mutation):
    h = historical
    source = await capture_source(h, monkeypatch)
    request = source.request
    if mutation == "future":
        headers, heights = make_headers(h.old.height, source.w.head.height + 1)
        source.w.headers.update(headers)
        source.w.heights.update(heights)
    if mutation == "proof":
        source.archive.proofs = {k: ["0x626164"] for k in source.archive.proofs}
    if mutation == "value":
        key = next(k for k, value in source.archive.values.items() if len(value or "") > 20)
        source.archive.values[key] += "00"

    async def changed(method, params):
        value = await request(method, params)
        if method == "chain_getBlockHash" and params == (h.old.height,) and mutation == "hash":
            return "https://not-a-hash"
        if method == "chain_getHeader" and params == (source.w.original.block_hash,):
            if mutation == "number":
                return {**value, "number": hex(h.old.height + 1)}
            if mutation == "parent":
                return {**value, "parentHash": "0x" + "aa" * 32}
        return value

    h.item.provider._registration_rpc.request = changed
    height = h.old.height if mutation != "future" else source.w.head.height + 1
    with pytest.raises((ValueError, ValidatorChainError)):
        await h.item.provider.capture_control_at(h.item.hotkey, height)


async def test_capture_requires_owned_provider_and_obeys_close(historical):
    h = historical
    with pytest.raises(ValueError, match="owned chain provider"):
        await h.item.provider.capture_control_at(h.item.hotkey, h.old.height)
    await h.item.provider.aclose()
    with pytest.raises(ValueError, match="owned chain provider"):
        await h.item.provider.capture_control_at(h.item.hotkey, h.old.height)


async def test_proven_historical_absence_does_not_become_admission(historical, monkeypatch):
    h = historical
    del h.item.rpc.values[h.item.spec]
    await capture_source(h, monkeypatch)
    result = await h.item.provider.capture_control_at(h.item.hotkey, h.old.height)
    check(h, result)
    assert result.control_sha256 is None and result.committed_at_block is None
    assert not json.loads(result.evidence)["chain_submission_authorized"]


async def test_cancellation_drains_capture_proof_before_unlock(historical, monkeypatch):
    import asyncio
    import threading

    h = historical
    await capture_source(h, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    verify = h.item.verifier.verify_many

    def blocked(**kwargs):
        entered.set()
        assert release.wait(10)
        return verify(**kwargs)

    monkeypatch.setattr(h.item.verifier, "verify_many", blocked)
    task = asyncio.create_task(h.item.provider.capture_control_at(h.item.hotkey, h.old.height))
    closing = None
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        closing = asyncio.create_task(h.item.provider.aclose())
        await asyncio.sleep(0.02)
        assert not task.done() and not closing.done() and h.item.provider._lock.locked()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await closing


@pytest.mark.parametrize("schema", [[], {}, None, 1])
async def test_malformed_archive_schema_is_a_validation_error(historical, schema):
    from umi.protocol import canonical_json_bytes

    h = historical
    body = {**json.loads(h.raw), "schema": schema}
    with pytest.raises(ValueError, match="exact native evidence"):
        await h.item.provider.review_control(canonical_json_bytes(body), h.metadata)
