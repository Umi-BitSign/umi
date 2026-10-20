"""Retained headers stay untrusted and replay from genuine owned ancestry."""

import asyncio
import threading

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.finalized_ancestry import MAXIMUM_HEADER_BYTES, encode_rpc_header
from umi.historical_header_recovery import HistoricalHeaderRecovery, HistoricalHeaderRecoveryPending

from .test_competition_reward_control_archive import (
    _linked_history,
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
from .test_historical_header_recovery import finish
from .test_historical_header_recovery import walk as walk


async def test_imported_local_hints_need_owned_ancestry_and_survive_restart(walk):
    w = walk
    headers = tuple(encode_rpc_header(v) for v in w.headers.values())
    recovery = HistoricalHeaderRecovery(w.connect)
    assert await recovery.retain_hints(headers) == len(headers)
    assert not recovery._verified and recovery._anchor is None
    assert await recovery.retain_hints(headers) == 0

    async def offline(*_):
        pytest.fail("retained headers must not be downloaded again")

    w.request = offline
    result = await finish(recovery, w)
    assert result.snapshot == w.target
    restarted = HistoricalHeaderRecovery(w.connect)
    assert not restarted._verified
    assert (await finish(restarted, w)).snapshot == w.target


async def test_hint_import_capacity_failure_is_atomic_and_resumable(walk):
    w = walk
    headers = tuple(encode_rpc_header(v) for v in w.headers.values())
    recovery = HistoricalHeaderRecovery(w.connect, maximum_bytes=sum(map(len, headers)) - 1)
    with pytest.raises(HistoricalHeaderRecoveryPending, match="capacity"):
        await recovery.retain_hints(headers)
    with w.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM historical_header_hints").fetchone() == (0,)
    recovery.maximum_bytes += 1
    assert await recovery.retain_hints(headers) == len(headers)
    assert (await finish(recovery, w)).snapshot == w.target


async def test_import_does_not_replace_a_damaged_retained_hint(walk):
    w = walk
    headers = tuple(encode_rpc_header(v) for v in w.headers.values())
    recovery = HistoricalHeaderRecovery(w.connect)
    await recovery.retain_hints(headers[:1])
    key = next(iter(w.headers))
    with w.connect() as db:
        db.execute("UPDATE historical_header_hints SET encoded=? WHERE hash=?", ("0x00", key))
    with pytest.raises(ValueError, match="hint changed"):
        await recovery.retain_hints(headers)
    with w.connect() as db:
        assert db.execute("SELECT hash,encoded FROM historical_header_hints").fetchall() == [
            (key, "0x00")
        ]
    assert not recovery._verified


@pytest.mark.parametrize(
    "invalid", [(), ("0x00",) * 4097, ("0x" + "0" * (2 * MAXIMUM_HEADER_BYTES + 2),)]
)
async def test_invalid_or_unbounded_import_does_not_open_storage(walk, invalid):
    def forbidden():
        pytest.fail("invalid headers must be rejected before storage")

    recovery = HistoricalHeaderRecovery(forbidden)
    with pytest.raises(ValueError):
        await recovery.retain_hints(invalid)


async def test_cancelled_import_drains_commit_and_can_repeat_without_rewrite(walk, monkeypatch):
    w = walk
    headers = tuple(encode_rpc_header(v) for v in w.headers.values())
    recovery = HistoricalHeaderRecovery(w.connect)
    entered, release = threading.Event(), threading.Event()
    retain = recovery._retain_hints

    def blocked(records):
        result = retain(records)
        entered.set()
        release.wait(5)
        return result

    monkeypatch.setattr(recovery, "_retain_hints", blocked)
    task = asyncio.create_task(recovery.retain_hints(headers))
    assert await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await recovery.retain_hints(headers) == 0
    assert (await finish(recovery, w)).snapshot == w.target


async def test_native_control_restore_uses_local_completed_headers_offline(historical, monkeypatch):
    h = historical
    w = await _linked_history(h, monkeypatch, 41)
    requests = []

    def source(first, last):
        requests.append((first, last))
        return tuple(encode_rpc_header(w.headers[w.heights[n]]) for n in range(first, last + 1))

    async def offline(*_):
        pytest.fail("completed local headers must avoid RPC")

    h.item.provider._registration_rpc.request = offline
    first = w.headers[w.original.block_hash]
    ref = FinalizedSnapshotRef(
        w.original.height, w.original.block_hash, first["parentHash"], first["stateRoot"]
    )
    encoded = encode_rpc_header(first)
    async with h.item.provider._lock:
        await h.item.provider._resolve_control_header(ref, encoded, retained_headers=source)
    assert requests == [(ref.block_number + 1, w.head.height - 1)]
    async with h.item.provider._lock:
        await h.item.provider._resolve_control_header(ref, encoded, retained_headers=source)
    assert len(requests) == 1
    proof = await h.item.provider.review_control(w.raw, w.metadata)
    assert proof.snapshot == ref and not w.calls
    await h.item.provider.aclose()
    h.item.provider = w.owned(h.reopen())
    h.item.provider._registration_rpc.request = offline
    assert (await h.item.provider.review_control(w.raw, w.metadata)).snapshot == ref


async def test_incorrect_local_header_order_cannot_issue_control(historical, monkeypatch):
    h = historical
    w = await _linked_history(h, monkeypatch, 41)
    first = w.headers[w.original.block_hash]
    ref = FinalizedSnapshotRef(
        w.original.height, w.original.block_hash, first["parentHash"], first["stateRoot"]
    )

    def wrong_order(low, high):
        return tuple(encode_rpc_header(w.headers[w.heights[n]]) for n in range(high, low - 1, -1))

    async with h.item.provider._lock:
        with pytest.raises(ValueError, match="wrong height"):
            await h.item.provider._resolve_control_header(
                ref, encode_rpc_header(first), retained_headers=wrong_order
            )
    assert not h.item.provider._historical_headers._verified
