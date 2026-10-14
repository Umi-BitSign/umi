"""Historical batches share only a scoped owned head, never a portable proof."""

import asyncio
from dataclasses import replace

import pytest

from umi.competition_reward_control_evidence import archive_header_hint

from .test_competition_reward_control_archive import chain as chain
from .test_competition_reward_control_archive import chain_config as chain_config
from .test_competition_reward_control_archive import control as control
from .test_competition_reward_control_archive import historical as historical
from .test_competition_reward_control_archive import policy as policy
from .test_competition_reward_control_archive import series_case as series_case


async def test_window_shares_one_owned_head_and_later_reads_refresh(historical, monkeypatch):
    h = historical
    provider = h.item.provider
    ref, header = archive_header_hint(h.raw)
    acquire = provider._proofs.finalized_snapshot
    heads = []

    async def counted():
        head = await acquire()
        heads.append(head)
        return head

    monkeypatch.setattr(provider._proofs, "finalized_snapshot", counted)
    async with provider._lock:
        async with provider._control_header_window() as resolve:
            expected = (h.old.timestamp_ms, h.fresh.timestamp_ms)
            assert await resolve(ref, header) == expected
            advanced = h.advance()
            assert await resolve(ref, header) == expected
            with pytest.raises(ValueError, match="ahead of owned finality"):
                await resolve(replace(ref, block_number=advanced.height), header)
        assert len(heads) == 1
        assert await provider._resolve_control_header(ref, header) == (
            h.old.timestamp_ms,
            advanced.timestamp_ms,
        )
        assert await provider._resolve_control_header(ref, header) == (
            h.old.timestamp_ms,
            advanced.timestamp_ms,
        )
    assert len(heads) == 3
    await provider.collect_control(h.item.hotkey)
    assert len(heads) == 4  # Current authority never borrows a historical head.


@pytest.mark.parametrize("failure", ["header", "state_root", "context"])
async def test_each_target_is_checked_inside_shared_window(historical, failure):
    h = historical
    provider = h.item.provider
    ref, header = archive_header_hint(h.raw)
    async with provider._lock, provider._control_header_window() as resolve:
        await resolve(ref, header)
        if failure == "header":
            header = "0x00"
        elif failure == "state_root":
            ref = replace(ref, state_root="0x" + "aa" * 32)
        else:
            h.blocks[ref.block_number] = replace(h.old, finality_verifier_sha256="aa" * 32)
        with pytest.raises(ValueError, match=r"header differs|binding mismatch"):
            await resolve(ref, header)


@pytest.mark.parametrize("exit_mode", ["normal", "exception"])
async def test_resolver_cannot_escape_task_or_window(historical, exit_mode):
    h = historical
    provider = h.item.provider
    ref, header = archive_header_hint(h.raw)
    async with provider._lock:
        try:
            async with provider._control_header_window() as resolve:
                with pytest.raises(ValueError, match="escaped"):
                    await asyncio.create_task(resolve(ref, header))
                assert await resolve(ref, header)
                if exit_mode == "exception":
                    raise RuntimeError("injected batch failure")
        except RuntimeError as error:
            assert str(error) == "injected batch failure"
        with pytest.raises(ValueError, match="escaped"):
            await resolve(ref, header)


async def test_cancelled_window_releases_lock_and_invalidates_resolver(historical):
    h = historical
    provider = h.item.provider
    ref, header = archive_header_hint(h.raw)
    entered = asyncio.Event()
    escaped = []

    async def batch():
        async with provider._lock, provider._control_header_window() as resolve:
            escaped.append(resolve)
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(batch())
    await asyncio.wait_for(entered.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not provider._lock.locked()
    async with provider._lock:
        with pytest.raises(ValueError, match="escaped"):
            await escaped[0](ref, header)
        assert await provider._resolve_control_header(ref, header)


async def test_window_requires_live_locked_provider_and_real_owned_head(historical):
    h = historical
    provider = h.item.provider
    with pytest.raises(ValueError, match="running locked provider"):
        async with provider._control_header_window():
            pytest.fail("unlocked provider issued a window")
    h.blocks.pop(h.fresh.height)
    async with provider._lock:
        with pytest.raises(ValueError, match="owned finality evidence is unavailable"):
            async with provider._control_header_window():
                pytest.fail("missing owned finality issued a window")
    await provider.aclose()
    async with provider._lock:
        with pytest.raises(ValueError, match="running locked provider"):
            async with provider._control_header_window():
                pytest.fail("closed provider issued a window")
