"""Completed original-owner history keeps its finality work across restart."""

from dataclasses import replace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_reward_checkpoint_tip import validate_checkpoint_tip
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.validator_chain import ValidatorChainError

from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


async def test_cold_owner_restarts_reuse_completed_finality_without_headers_or_proofs(
    history_case, monkeypatch
):
    h = history_case
    expected = await h.reader.advance(h.item.provider, through_block=h.end)
    prefix = await h.reader.verified_prefix(h.old.height + 1)
    h.offline_through = h.end

    def forbidden(*args, **kwargs):
        pytest.fail("completed historical header or proof work was repeated")

    for _ in range(3):
        h.reader = await h.restart()  # Reopens both the provider and native reader.
        provider = h.item.provider
        assert await provider._finality.verified_block_at(h.end) is None
        fresh, calls = provider._finality.verified_finalized_snapshot, []

        async def current_head(fresh=fresh, calls=calls):
            calls.append(1)
            return await fresh()

        monkeypatch.setattr(provider._finality, "verified_finalized_snapshot", current_head)
        monkeypatch.setattr(provider._historical_headers, "recover", forbidden)
        monkeypatch.setattr(provider._historical_headers, "retain_hints", forbidden)
        monkeypatch.setattr(h.reader.checkpoints, "header_hints", forbidden)
        monkeypatch.setattr(h.reader, "_load", forbidden)
        h.rpc_calls.clear()
        assert await h.reader.advance(provider, through_block=h.end) == expected
        assert await h.reader.verified_prefix(h.old.height + 1) == prefix
        assert calls and not h.rpc_calls
        assert h.reader.progress.native_completed == 0
        assert h.reader.progress.latest["completed_tip_finality_refreshes"] == 1
        # Undo the wrapper before the next restart; the fixture shares finality.
        monkeypatch.setattr(provider._finality, "verified_finalized_snapshot", fresh)


async def test_completed_tip_still_requires_a_fresh_owned_head(history_case, monkeypatch):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()

    async def unavailable():
        raise OSError("owned observer temporarily unavailable")

    monkeypatch.setattr(h.item.provider._finality, "verified_finalized_snapshot", unavailable)
    with pytest.raises(Exception, match="owned_finality_unavailable"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.reader.first_block
    assert h.reader.progress.native_completed == 0


@pytest.mark.parametrize("entry", ["provider", "reader"])
async def test_serialized_checkpoint_cannot_select_native_reuse(history_case, entry):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    value = h.reader.checkpoints.load(h.end)
    provider = h.item.provider
    if entry == "reader":
        with pytest.raises(ValueError, match="another history owner"):
            await h.reader._validate_checkpoint_tip(
                provider, value, completed_checkpoint=dict(value)
            )
        return
    async with provider._lock:
        with pytest.raises(ValueError, match="native owner result"):
            await provider._resolve_control_header(
                expected_snapshot(value), value["header"], completed_checkpoint=dict(value)
            )


def expected_snapshot(value):
    return FinalizedSnapshotRef(**value["snapshot"])


@pytest.mark.parametrize(
    "field", ["snapshot", "encoded_header", "chain_config_sha256", "semantics"]
)
async def test_changed_capability_is_not_reusable(history_case, field):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    values, tip = h.reader.checkpoints.load_restore_batch(h.old.height, h.end)
    changed = (
        replace(tip.snapshot, block_number=tip.snapshot.block_number + 1)
        if field == "snapshot"
        else "0x00"
        if field == "encoded_header"
        else "00" * 32
    )
    forged = replace(tip, **{field: changed})
    with pytest.raises(ValueError, match="native owner result"):
        validate_checkpoint_tip(
            forged,
            snapshot=expected_snapshot(values[-1]),
            encoded_header=values[-1]["header"],
            chain_config_sha256=h.reader.config_sha256,
        )


async def test_batch_capability_does_not_cross_history_owner_instances(history_case):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    values, tip = h.reader.checkpoints.load_restore_batch(h.old.height, h.end)
    reopened = h.new_reader()
    with pytest.raises(ValueError, match="another history owner"):
        await reopened._validate_checkpoint_tip(
            h.item.provider, values[-1], completed_checkpoint=tip
        )
    assert reopened._next == reopened.first_block


async def test_changed_completed_sources_cannot_issue_a_tip(history_case):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    with h.reader.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
            (str(h.end),),
        )
    with pytest.raises(HistoryCheckpointRepairRequired, match="source changed"):
        h.reader.checkpoints.load_restore_batch(h.old.height, h.end)


async def test_completed_boundary_ahead_of_fresh_owned_head_is_refused(history_case, monkeypatch):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()
    original = h.source.w.original
    monkeypatch.setitem(h.blocks, original.height, original)

    async def earlier_head():
        return FinalizedSnapshotRef(
            original.height,
            original.block_hash,
            h.source.w.headers[original.block_hash]["parentHash"],
            original.state_root,
        )

    monkeypatch.setattr(h.item.provider._finality, "verified_finalized_snapshot", earlier_head)
    with pytest.raises(ValueError, match="ahead of owned finality"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.reader.first_block


async def test_conflicting_original_observer_record_remains_a_refusal(history_case, monkeypatch):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()
    finality = h.item.provider._finality
    at = finality.verified_block_at
    original = h.source.w.original

    async def conflicting_record(height):
        if height == h.end:
            return replace(original, height=height, block_hash="0x" + "00" * 32)
        return await at(height)

    monkeypatch.setattr(finality, "verified_block_at", conflicting_record)
    with pytest.raises((ValueError, ValidatorChainError)):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.reader.first_block


async def test_plain_archive_keeps_ancestry_verification(history_case, monkeypatch):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = await h.restart()
    value = h.reader.checkpoints.load(h.end)
    recover = h.item.provider._historical_headers.recover
    calls = []

    async def counted(*args, **kwargs):
        calls.append(1)
        return await recover(*args, **kwargs)

    monkeypatch.setattr(h.item.provider._historical_headers, "recover", counted)
    await h.reader._validate_checkpoint_tip(h.item.provider, dict(value))
    assert calls == [1]
    assert h.reader.progress.completed_tip_refreshes == 0


async def test_changed_owner_semantics_cannot_borrow_an_older_tip(history_case):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    values, tip = h.reader.checkpoints.load_restore_batch(h.old.height, h.end)
    h.reader.checkpoints.semantics = "00" * 32
    with pytest.raises(ValueError, match="native owner result"):
        validate_checkpoint_tip(
            tip,
            snapshot=expected_snapshot(values[-1]),
            encoded_header=values[-1]["header"],
            chain_config_sha256=h.reader.config_sha256,
        )
