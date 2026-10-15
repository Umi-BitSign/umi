"""Historical batches share only a scoped owned head, never a portable proof."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_reward_control_evidence import archive_header_hint
from umi.competition_reward_writer_prefix import restore_completed_prefix

from .test_competition_reward_control_archive import chain as chain
from .test_competition_reward_control_archive import chain_config as chain_config
from .test_competition_reward_control_archive import control as control
from .test_competition_reward_control_archive import historical as historical
from .test_competition_reward_control_archive import policy as policy
from .test_competition_reward_control_archive import series_case as series_case
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay


async def test_window_shares_one_owned_head_and_later_reads_refresh(historical, monkeypatch):
    h = historical
    provider = h.item.provider
    ref, header = archive_header_hint(h.raw)
    acquire = provider._finality.verified_finalized_snapshot
    collect = provider._proofs.finalized_snapshot
    heads, collected_heads = [], []

    async def counted():
        head = await acquire()
        heads.append(head)
        return head

    async def collected():
        head = await collect()
        collected_heads.append(head)
        return head

    monkeypatch.setattr(provider._finality, "verified_finalized_snapshot", counted)
    monkeypatch.setattr(provider._proofs, "finalized_snapshot", collected)
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
    assert collected_heads == []
    await provider.collect_control(h.item.hotkey)
    assert len(collected_heads) == 1  # Current authority still uses the proof collector.


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize("consumer", ["reader", "writer_prefix"])
async def test_completed_prefix_restart_needs_neither_transport_nor_payload_replay(
    history_case, monkeypatch, consumer
):
    h = history_case
    expected = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    owner, inode = h.reader.checkpoints.owner, h.reader.journal.path.stat().st_ino
    completed = {
        height: h.reader.checkpoints.load(height)
        for height in range(h.reader.first_block, h.end + 1)
    }

    async def unavailable(*_):
        pytest.fail("completed historical prefix must not contact either RPC transport")

    owner_checks = []

    async def recheck():
        owner_checks.append(h.reader.checkpoints.owner)

    # Reopen the provider too: this discards process ancestry caches, while the
    # retained hints and successful block checkpoints remain independently owned.
    for _ in range(2):
        h.reader = await h.restart()
        prohibit_proof_replay(monkeypatch, h.reader)
        provider = h.item.provider
        monkeypatch.setattr(provider._proofs, "finalized_snapshot", unavailable)
        monkeypatch.setattr(provider._proofs._rpc, "request", unavailable)
        monkeypatch.setattr(provider._registration_rpc, "request", unavailable)
        if consumer == "reader":
            actual = (await h.reader.advance(provider, through_block=h.end)).history
        else:
            actual = await restore_completed_prefix(
                h.reader,
                provider,
                through_block=h.end,
                maximum_blocks=2,
                owner=SimpleNamespace(recheck=recheck),
            )
        assert actual == expected
        assert h.reader.checkpoints.owner == owner
        assert h.reader.journal.path.stat().st_ino == inode
        assert h.reader.progress.native_completed == 0
        assert h.reader.progress.restored_completed == len(completed)
        assert {height: h.reader.checkpoints.load(height) for height in completed} == completed
    if consumer == "writer_prefix":
        assert owner_checks and set(owner_checks) == {owner}


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
