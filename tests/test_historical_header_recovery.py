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
