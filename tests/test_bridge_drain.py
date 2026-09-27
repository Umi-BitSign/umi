"""Synthetic ancestry/body proofs only; no live marker or recovery transaction."""

from __future__ import annotations

import asyncio
import hashlib
import threading

import pytest

from tests.test_bridge_receipt_provider import provider as provider
from tests.test_bridge_receipts import history as history
from tests.test_bridge_transactions import case as case
from tests.test_bridge_transactions import signed_policy as signed_policy
from tests.test_bridge_transactions import tx as tx
from umi.bridge.drain import MARKER_DOMAIN, LegacyDrainReader
from umi.bridge.policy import RegistrationBridgeError
from umi.chain import _header_hash
from umi.protocol import canonical_json_bytes

MARKER = MARKER_DOMAIN + bytes(range(32))


def install_body(history, number, body):
    """Reseal the synthetic chain so mutations aren't trusted RPC assertions."""
    parent = history.hashes[number - 1]
    for height in range(number, history.birth + 201):
        prior = history.hashes[height]
        raw = dict(history.headers[prior])
        items = body if height == number else history.bodies[prior]
        raw.update(
            parentHash=parent,
            number=height,
            extrinsicsRoot="0x" + hashlib.sha256(b"".join(items)).hexdigest(),
        )
        block_hash = _header_hash(raw, "test drain")
        history.hashes[height] = block_hash
        history.headers[block_hash] = {**raw, "number": hex(height)}
        history.bodies[block_hash] = items
        parent = block_hash


@pytest.fixture
def drain(history):
    number = history.birth + 2
    install_body(history, number, (b"inherent", b"signed remark:" + MARKER))
    history.head = number + 8
    history.drain = LegacyDrainReader(history.reader)
    history.locator = dict(marker=MARKER, block_number=number, block_hash=history.hashes[number])
    return history


async def read(drain):
    return await drain.drain.read(**drain.locator)


async def find(drain):
    return await drain.drain.find(
        marker=MARKER, birth_block=drain.birth, birth_hash=drain.hashes[drain.birth], period=64
    )


async def test_search_finds_marker_without_a_submission_receipt(drain):
    result = await find(drain)
    assert result.included.block_number == drain.birth + 2
    assert result.owned_head.block_number == drain.birth + 10
    assert result.extrinsic_indices == (1,)
    assert await find(drain) is result
    assert all(method in {"chain_getHeader", "chain_getBlock"} for method, _ in drain.calls)


async def test_search_waits_for_eight_blocks_then_keeps_completed_body_work(drain):
    drain.head = drain.birth + 9
    assert await find(drain) is None
    first_bodies = [params for method, params in drain.calls if method == "chain_getBlock"]
    assert first_bodies == [(drain.hashes[drain.birth + 1],)]
    drain.head += 1
    assert (await find(drain)).included.block_number == drain.birth + 2
    assert [params for method, params in drain.calls if method == "chain_getBlock"].count(
        first_bodies[0]
    ) == 1


async def test_search_checks_signing_ancestry_even_after_finding_marker(drain):
    with pytest.raises(RegistrationBridgeError, match="signing_ancestry_mismatch"):
        await drain.drain.find(
            marker=MARKER, birth_block=drain.birth, birth_hash="0x" + "ff" * 32, period=64
        )
    assert drain.drain._search_result is None


async def test_search_never_extends_past_the_signed_era(drain):
    install_body(drain, drain.birth + 2, (b"empty",))
    install_body(drain, drain.birth + 64, (MARKER,))
    drain.head = drain.birth + 75
    assert await find(drain) is None
    bodies = [params for method, params in drain.calls if method == "chain_getBlock"]
    assert len(bodies) == 63
    count = len(drain.calls)
    assert await find(drain) is None and len(drain.calls) == count


async def test_provider_search_uses_owned_finality_and_rejects_after_close(provider, drain):
    args = dict(
        marker=MARKER, birth_block=drain.birth, birth_hash=drain.hashes[drain.birth], period=64
    )
    assert (await provider.find_legacy_drain(**args)).included.block_number == drain.birth + 2
    assert provider.proof_captures == 1 and drain.heads == 0
    await provider.aclose()
    with pytest.raises(ValueError, match="closed"):
        await provider.find_legacy_drain(**args)


async def test_proves_marker_inclusion_and_eight_blocks_without_changing_journal(drain):
    journal = canonical_json_bytes(drain.journal)
    result = await read(drain)
    assert result.included.block_number == drain.birth + 2
    assert result.included.block_hash == drain.locator["block_hash"]
    assert result.owned_head.block_number == result.included.block_number + 8
    assert result.extrinsic_indices == (1,)
    assert result.marker_sha256 == hashlib.sha256(MARKER).hexdigest()
    assert canonical_json_bytes(drain.journal) == journal
    assert all(method in {"chain_getHeader", "chain_getBlock"} for method, _ in drain.calls)
    assert drain.verified[-1][0] == "body"
    count = len(drain.calls)
    assert await read(drain) is result
    assert len(drain.calls) == count


@pytest.mark.parametrize("delta", [-1, 0, 7])
async def test_waits_for_owned_finality_and_retries_without_rpc_head_fallback(drain, delta):
    drain.head = drain.locator["block_number"] + delta
    with pytest.raises(RegistrationBridgeError, match="not_finalized"):
        await read(drain)
    assert not drain.calls and drain.drain._cursor is None
    drain.head = drain.locator["block_number"] + 8
    assert (await read(drain)).owned_head.block_number == drain.head


@pytest.mark.parametrize("target", ["owned", "ancestor", "marker"])
async def test_modified_header_never_produces_a_drain(drain, target):
    number = {"owned": drain.head, "ancestor": drain.head - 1, "marker": drain.birth + 2}[target]
    drain.headers[drain.hashes[number]]["stateRoot"] = "0x" + "99" * 32
    with pytest.raises(RegistrationBridgeError, match="header_mismatch"):
        await read(drain)
    assert not drain.verified and drain.drain._result is None


async def test_other_fork_locator_is_rejected(drain):
    drain.locator["block_hash"] = "0x" + "ff" * 32
    with pytest.raises(RegistrationBridgeError, match="ancestry_mismatch"):
        await read(drain)
    assert not drain.verified


@pytest.mark.parametrize("change", ["proof", "body", "response_header"])
async def test_unproven_block_body_is_rejected(drain, change):
    if change == "proof":
        drain.rejected_body = True
    elif change == "body":
        drain.bodies[drain.locator["block_hash"]] = (MARKER,)
    else:
        request = drain.rpc.request

        async def wrong_header(method, params):
            result = await request(method, params)
            if method == "chain_getBlock":
                result["block"]["header"] = drain.headers[drain.hashes[drain.head]]
            return result

        drain.rpc.request = wrong_header
    with pytest.raises(RegistrationBridgeError, match=r"body_root_invalid|header_mismatch"):
        await read(drain)
    assert drain.drain._result is None


@pytest.mark.parametrize("body", [(b"unrelated",), (MARKER[:25], MARKER[25:])])
async def test_marker_must_occur_whole_inside_one_proven_extrinsic(drain, body):
    number = drain.locator["block_number"]
    install_body(drain, number, body)
    drain.locator["block_hash"] = drain.hashes[number]
    with pytest.raises(RegistrationBridgeError, match="marker_not_included"):
        await read(drain)
    assert drain.verified[-1][0] == "body"


async def test_moving_the_locator_cannot_reuse_a_successful_result(drain):
    first = await read(drain)
    drain.locator.update(block_number=drain.birth + 1, block_hash=drain.hashes[drain.birth + 1])
    with pytest.raises(RegistrationBridgeError, match="marker_not_included"):
        await read(drain)
    assert drain.drain._result is None and first.included.block_number == drain.birth + 2


async def test_substituting_a_marker_cannot_reuse_a_successful_result(drain):
    await read(drain)
    drain.locator["marker"] = MARKER_DOMAIN + b"x" * 32
    with pytest.raises(RegistrationBridgeError, match="marker_not_included"):
        await read(drain)


@pytest.mark.parametrize(
    "field,value",
    [
        ("marker", b"x" * 32),
        ("marker", MARKER + b"x"),
        ("marker", bytearray(MARKER)),
        ("block_number", True),
        ("block_number", 0),
        ("block_number", 2**53),
        ("block_hash", "ff" * 32),
        ("block_hash", "0x" + "FF" * 32),
    ],
)
async def test_invalid_inputs_are_rejected_before_any_io(drain, field, value):
    drain.locator[field] = value
    with pytest.raises(RegistrationBridgeError, match="invalid"):
        await read(drain)
    assert not drain.calls and not drain.heads


@pytest.mark.parametrize("interrupt", ["timeout", "cancel"])
async def test_interrupted_hash_walk_resumes_without_growing_history(drain, interrupt):
    drain.head = drain.birth + 200
    original = drain.rpc.request
    pause_hash = drain.hashes[drain.birth + 130]
    entered = asyncio.Event()

    async def stalled(method, params):
        if method == "chain_getHeader" and params == (pause_hash,):
            entered.set()
            await asyncio.Event().wait()
        return await original(method, params)

    drain.rpc.request = stalled
    drain.reader._timeout = 0.05 if interrupt == "timeout" else 60
    task = asyncio.create_task(read(drain))
    await asyncio.wait_for(entered.wait(), 2)
    if interrupt == "cancel":
        task.cancel()
    with pytest.raises(asyncio.TimeoutError if interrupt == "timeout" else asyncio.CancelledError):
        await task
    assert not drain.drain._lock.locked()
    assert drain.drain._cursor.snapshot.block_number == drain.birth + 131
    drain.rpc.request = original
    drain.reader._timeout = 60
    count = len(drain.calls)
    result = await read(drain)
    assert result.included.block_number == drain.birth + 2
    assert drain.calls[count] == ("chain_getHeader", (pause_hash,))
    assert drain.heads == 1
    assert drain.reader.progress == (None, None, None, frozenset(), False, False)


async def test_new_process_rechecks_body_and_finality(drain):
    prior = await read(drain)
    drain.drain = LegacyDrainReader(drain.reader)
    count = len(drain.calls)
    assert await read(drain) == prior
    assert len(drain.calls) > count and drain.heads == 2


async def test_cancelled_native_body_proof_is_drained_before_releasing_owner(drain):
    entered, release = threading.Event(), threading.Event()
    original = drain.verifier.verify_extrinsics_root

    def blocked(**kwargs):
        entered.set()
        assert release.wait(5)
        return original(**kwargs)

    drain.verifier.verify_extrinsics_root = blocked
    task = asyncio.create_task(read(drain))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done() and drain.drain._lock.locked()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not drain.drain._lock.locked() and drain.drain._result is None
    assert (await read(drain)).included.block_number == drain.birth + 2


async def test_provider_uses_its_own_finality_and_closes_cached_drain(provider, drain):
    result = await provider.read_legacy_drain(**drain.locator)
    assert result.included.block_number == drain.birth + 2
    assert provider.proof_captures == 1 and drain.heads == 0
    assert await provider.read_legacy_drain(**drain.locator) is result
    await provider.aclose()
    assert provider._legacy_drain is None and provider.rpc_closed
    with pytest.raises(ValueError, match="closed"):
        await provider.read_legacy_drain(**drain.locator)


@pytest.mark.parametrize("missing", ["owner", "task", "runtime", "rpc"])
async def test_cached_drain_cannot_bypass_provider_ownership(provider, drain, missing):
    await provider.read_legacy_drain(**drain.locator)
    if missing == "owner":
        provider._owned = False
    elif missing == "task":
        provider._task = None
    elif missing == "runtime":
        provider._runtime_executor = None
    else:
        provider._weight_rpc = None
    with pytest.raises(ValueError, match=r"owned|observer"):
        await provider.read_legacy_drain(**drain.locator)


@pytest.mark.parametrize("progress", [False, True])
async def test_provider_retries_timeout_only_after_verified_progress(
    provider, drain, monkeypatch, progress
):
    original = LegacyDrainReader.read
    calls = 0

    async def interrupted(reader, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            if progress:
                await original(reader, **kwargs)
            raise asyncio.TimeoutError("injected lost response")
        return await original(reader, **kwargs)

    monkeypatch.setattr(LegacyDrainReader, "read", interrupted)
    if progress:
        result = await provider.read_legacy_drain(**drain.locator)
        assert result.included.block_number == drain.birth + 2 and calls == 2
    else:
        with pytest.raises(asyncio.TimeoutError, match="lost response"):
            await provider.read_legacy_drain(**drain.locator)
        assert calls == 1
    assert not provider._lock.locked()


async def test_provider_close_drains_cancelled_marker_proof(provider, drain, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = drain.verifier.verify_extrinsics_root

    def blocked(**kwargs):
        entered.set()
        assert release.wait(5)
        return original(**kwargs)

    monkeypatch.setattr(drain.verifier, "verify_extrinsics_root", blocked)
    capture = asyncio.create_task(provider.read_legacy_drain(**drain.locator))
    close = None
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        capture.cancel()
        close = asyncio.create_task(provider.aclose())
        await asyncio.sleep(0.02)
        assert not capture.done() and not close.done() and not provider.rpc_closed
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await capture
        if close is not None:
            await close
    assert provider._legacy_drain is None and provider.rpc_closed
