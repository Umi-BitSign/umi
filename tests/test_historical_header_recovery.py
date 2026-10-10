"""Native durable header hints with synthetic linked Substrate headers."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from dataclasses import replace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.finalized_ancestry import encode_rpc_header
from umi.historical_header_recovery import HistoricalHeaderRecovery, HistoricalHeaderRecoveryPending

from .test_competition_chain import chain_config as chain_config
from .test_finalized_ancestry import make_anchor, make_headers
from .test_open_competition import policy as policy


@pytest.fixture
def walk(tmp_path, chain_config, policy, request):
    from types import SimpleNamespace

    first = chain_config.minimum_finalized_block + 10
    distance = 2050 if "gap_beyond" in request.node.name else 40
    headers, by_height = make_headers(first, first + distance)
    anchor = make_anchor(chain_config, policy, headers, by_height)
    oldest = headers[by_height[first]]
    target = FinalizedSnapshotRef(
        first, by_height[first], oldest["parentHash"], oldest["stateRoot"]
    )
    path = tmp_path / "headers.sqlite3"

    def connect():
        db = sqlite3.connect(path, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        return db

    calls = []

    async def request(method, params):
        assert method == "chain_getHeader"
        calls.append(params[0])
        return headers[params[0]]

    return SimpleNamespace(
        anchor=anchor,
        target=target,
        headers=headers,
        by_height=by_height,
        connect=connect,
        calls=calls,
        request=request,
    )


async def finish(recovery, w):
    for _ in range(100):
        try:
            return await recovery.recover(w.anchor, w.target, w.request)
        except HistoricalHeaderRecoveryPending:
            pass
    pytest.fail("recovery did not converge")


async def test_gap_beyond_2048_resumes_after_restart_without_refetching(walk):
    w = walk
    service = HistoricalHeaderRecovery(w.connect, batch_size=256)
    for _ in range(3):
        with pytest.raises(HistoricalHeaderRecoveryPending):
            await service.recover(w.anchor, w.target, w.request)
    assert len(w.calls) == 768
    restarted = HistoricalHeaderRecovery(w.connect, batch_size=256)
    assert (await finish(restarted, w)).snapshot == w.target
    assert len(w.calls) == len(set(w.calls)) == w.anchor.height - w.target.block_number
    assert (await finish(HistoricalHeaderRecovery(w.connect), w)).snapshot == w.target
    assert len(w.calls) == 2050


async def test_cancelled_download_preserves_prior_links(walk):
    w = walk
    entered = asyncio.Event()

    async def interrupted(method, params):
        if len(w.calls) == 7:
            entered.set()
            await asyncio.Future()
        return await w.request(method, params)

    service = HistoricalHeaderRecovery(w.connect)
    task = asyncio.create_task(service.recover(w.anchor, w.target, interrupted))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (await finish(HistoricalHeaderRecovery(w.connect), w)).snapshot == w.target
    assert len(w.calls) == len(set(w.calls)) == w.anchor.height - w.target.block_number


async def test_capacity_increase_resumes_same_target(walk):
    w = walk
    service = HistoricalHeaderRecovery(w.connect, maximum_bytes=600)
    with pytest.raises(HistoricalHeaderRecoveryPending, match="capacity"):
        await service.recover(w.anchor, w.target, w.request)
    with w.connect() as db:
        retained = db.execute("SELECT COUNT(*) FROM historical_header_hints").fetchone()[0]
    assert retained > 0
    assert (await finish(HistoricalHeaderRecovery(w.connect), w)).snapshot == w.target
    assert (
        len(w.calls) == w.anchor.height - w.target.block_number + 1
    )  # The uncommitted header alone needed another fetch.


@pytest.mark.parametrize("mode", ["download", "hint", "target", "anchor"])
async def test_mismatching_header_never_returns_historical_identity(walk, mode):
    w = walk
    service = HistoricalHeaderRecovery(w.connect, batch_size=4)
    with pytest.raises(HistoricalHeaderRecoveryPending):
        await service.recover(w.anchor, w.target, w.request)
    if mode == "download":
        key = w.by_height[w.anchor.height - 5]
        w.headers[key]["stateRoot"] = "0x" + "ff" * 32
    elif mode == "hint":
        with w.connect() as db:
            db.execute(
                "UPDATE historical_header_hints SET encoded=?",
                (encode_rpc_header(w.headers[w.target.block_hash]),),
            )
        service = HistoricalHeaderRecovery(w.connect)
    elif mode == "target":
        w.target = replace(w.target, state_root="0x" + "ff" * 32)
    else:
        w.anchor = replace(w.anchor, block_hash="0x" + "ff" * 32)
    with pytest.raises(ValueError):
        await finish(service, w)


async def test_failed_hint_write_never_advances_cursor(walk):
    w = walk
    service = HistoricalHeaderRecovery(w.connect)
    assert service._load(w.target.block_hash) is None
    with w.connect() as db:
        db.execute(
            "CREATE TRIGGER fail_hint BEFORE INSERT ON historical_header_hints "
            "BEGIN SELECT RAISE(ABORT, 'injected disk failure'); END"
        )
    with pytest.raises(sqlite3.Error):
        await service.recover(w.anchor, w.target, w.request)
    assert service.progress == {}
    with w.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM historical_header_hints").fetchone()[0] == 0
        db.execute("DROP TRIGGER fail_hint")
    assert (await finish(service, w)).snapshot == w.target


async def test_byte_budget_yields_without_expiring_target(walk, monkeypatch):
    w = walk
    monkeypatch.setattr("umi.historical_header_recovery.MAXIMUM_PATH_BYTES", 2500)
    service = HistoricalHeaderRecovery(w.connect, batch_size=4096)
    with pytest.raises(HistoricalHeaderRecoveryPending):
        await service.recover(w.anchor, w.target, w.request)
    assert 1 < len(w.calls) < 30
    monkeypatch.setattr("umi.historical_header_recovery.MAXIMUM_PATH_BYTES", 1024 * 1024)
    assert (await finish(service, w)).snapshot == w.target


async def test_lost_storage_acknowledgement_reuses_durable_header(walk, monkeypatch):
    w = walk
    service = HistoricalHeaderRecovery(w.connect)
    original = service._save

    def lost(*args):
        original(*args)
        raise OSError("acknowledgement lost after commit")

    monkeypatch.setattr(service, "_save", lost)
    with pytest.raises(OSError):
        await service.recover(w.anchor, w.target, w.request)
    assert service.progress == {}
    assert (await finish(HistoricalHeaderRecovery(w.connect), w)).snapshot == w.target
    assert len(w.calls) == len(set(w.calls)) == w.anchor.height - w.target.block_number


async def test_cancelled_header_persistence_drains_before_releasing_owner(walk, monkeypatch):
    w = walk
    service = HistoricalHeaderRecovery(w.connect)
    original = service._save
    entered, release = threading.Event(), threading.Event()

    def blocked(*args):
        entered.set()
        assert release.wait(10)
        original(*args)

    monkeypatch.setattr(service, "_save", blocked)
    task = asyncio.create_task(service.recover(w.anchor, w.target, w.request))
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done() and service.progress == {}
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (await finish(HistoricalHeaderRecovery(w.connect), w)).snapshot == w.target
    assert len(w.calls) == len(set(w.calls)) == w.anchor.height - w.target.block_number


async def test_complete_interval_reuses_links_only_within_the_owned_anchor(walk, monkeypatch):
    w = walk
    service = HistoricalHeaderRecovery(w.connect)
    loaded, load = [], service._load

    def counted(block_hash):
        loaded.append(block_hash)
        return load(block_hash)

    monkeypatch.setattr(service, "_load", counted)
    assert (await finish(service, w)).snapshot == w.target
    expected = len(w.headers) - 1
    assert len(loaded) == len(w.calls) == expected
    for height in range(w.target.block_number, w.anchor.height):
        block_hash = w.by_height[height]
        header = w.headers[block_hash]
        target = FinalizedSnapshotRef(height, block_hash, header["parentHash"], header["stateRoot"])
        assert (await service.recover(w.anchor, target, w.request)).snapshot == target
    assert len(loaded) == len(w.calls) == expected
    assert service.progress == {}

    # Process-local verified links do not become durable trust on restart.
    restarted = HistoricalHeaderRecovery(w.connect)
    monkeypatch.setattr(restarted, "_load", counted)
    assert (await finish(restarted, w)).snapshot == w.target
    assert len(loaded) == 2 * expected and len(w.calls) == expected


@pytest.mark.parametrize("field", ["block_number", "parent_hash", "state_root"])
async def test_verified_link_reuse_requires_the_exact_target(walk, field):
    w = walk
    service = HistoricalHeaderRecovery(w.connect)
    await finish(service, w)
    value = w.target.block_number + 1 if field == "block_number" else "0x" + "ff" * 32
    with pytest.raises(ValueError, match="differs from finalized ancestry"):
        await service.recover(w.anchor, replace(w.target, **{field: value}), w.request)


async def test_adjacent_older_target_continues_from_verified_descendant(walk, monkeypatch):
    w = walk
    original = w.target
    height = original.block_number + 1
    block_hash = w.by_height[height]
    header = w.headers[block_hash]
    w.target = FinalizedSnapshotRef(height, block_hash, header["parentHash"], header["stateRoot"])
    service = HistoricalHeaderRecovery(w.connect, batch_size=4)
    assert (await finish(service, w)).snapshot == w.target
    loaded, load = [], service._load

    def counted(block_hash):
        loaded.append(block_hash)
        return load(block_hash)

    monkeypatch.setattr(service, "_load", counted)
    assert (await service.recover(w.anchor, original, w.request)).snapshot == original
    assert loaded == [original.block_hash]
    assert len(w.calls) == len(set(w.calls)) == w.anchor.height - original.block_number


async def test_new_anchor_rechecks_durable_links(walk, monkeypatch, chain_config, policy):
    w = walk
    service = HistoricalHeaderRecovery(w.connect)
    await finish(service, w)
    lower = {n: h for n, h in w.by_height.items() if n < w.anchor.height - 10}
    w.anchor = make_anchor(chain_config, policy, w.headers, lower)
    loaded, load = [], service._load

    def counted(block_hash):
        loaded.append(block_hash)
        return load(block_hash)

    monkeypatch.setattr(service, "_load", counted)
    assert (await finish(service, w)).snapshot == w.target
    assert len(loaded) == w.anchor.height - w.target.block_number


async def test_verified_memory_eviction_preserves_recoverability(walk, monkeypatch):
    w = walk
    monkeypatch.setattr("umi.historical_header_recovery.MAXIMUM_VERIFIED_HEADER_BYTES", 600)
    service = HistoricalHeaderRecovery(w.connect)
    await finish(service, w)
    assert 0 < service._verified_bytes <= 600
    height = w.anchor.height - 1
    block_hash = w.by_height[height]
    header = w.headers[block_hash]
    target = FinalizedSnapshotRef(height, block_hash, header["parentHash"], header["stateRoot"])
    assert height not in service._verified
    assert (await service.recover(w.anchor, target, w.request)).snapshot == target
    assert service._verified_bytes <= 600
    assert (await finish(service, w)).snapshot == w.target
    assert len(w.calls) == len(set(w.calls)) == len(w.headers) - 1


async def test_alternating_owned_anchors_preserve_each_pending_walk(walk, chain_config, policy):
    w = walk
    lower = {n: h for n, h in w.by_height.items() if n < w.anchor.height - 10}
    anchors = (w.anchor, make_anchor(chain_config, policy, w.headers, lower))
    service = HistoricalHeaderRecovery(w.connect, batch_size=4)
    completed = set()
    for _ in range(12):
        for anchor in anchors:
            if anchor.height in completed:
                continue
            try:
                result = await service.recover(anchor, w.target, w.request)
            except HistoricalHeaderRecoveryPending:
                continue
            assert result.snapshot == w.target
            completed.add(anchor.height)
    assert completed == {a.height for a in anchors}
    assert len(w.calls) == len(set(w.calls)) == w.anchor.height - w.target.block_number


async def test_gap_beyond_2048_recovers_height_without_rpc_hash_claim(walk):
    w = walk
    service = HistoricalHeaderRecovery(w.connect, batch_size=256)
    for _ in range(12):
        try:
            result = await service.recover_height(w.anchor, w.target.block_number, w.request)
            break
        except HistoricalHeaderRecoveryPending:
            pass
    else:
        pytest.fail("height recovery did not converge")
    assert result.snapshot == w.target
    assert len(w.calls) == len(set(w.calls)) == 2050
    assert (await service.recover(w.anchor, w.target, w.request)).snapshot == w.target
    assert len(w.calls) == 2050
