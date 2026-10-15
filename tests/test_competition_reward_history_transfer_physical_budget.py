"""Native retained fact/export/ordered restore through explicit physical limits."""

import hashlib

import pytest

from umi.competition_journal_physical_budget import ArchivePhysicalBudget, JournalPhysicalBudget
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_proof_archive import RewardProofArchive

from .test_competition_reward_history_checkpoints import prohibit_proof_replay
from .test_competition_reward_history_transfer import chain as chain
from .test_competition_reward_history_transfer import chain_config as chain_config
from .test_competition_reward_history_transfer import control as control
from .test_competition_reward_history_transfer import historical as historical
from .test_competition_reward_history_transfer import history_case as history_case
from .test_competition_reward_history_transfer import policy as policy
from .test_competition_reward_history_transfer import series_case as series_case
from .test_competition_reward_history_transfer import transfer_case as transfer_case

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


async def test_bounded_open_transfer_export_native_restore_restart_and_repeat(
    transfer_case, tmp_path, monkeypatch
):
    h = transfer_case
    original_source = h.source
    source_hash = hashlib.sha256(original_source.journal.path.read_bytes()).hexdigest()
    context = dict(
        control_hotkey=h.source.hotkey,
        chain_config_sha256=h.source.config_sha256,
        first_block=h.source.first_block,
    )
    h.source = RewardControlHistoryReader(
        h.source.journal.root, **context, existing_only=True, read_only=True
    )
    budget = JournalPhysicalBudget(h.target.journal.path.stat().st_size + 64 * 1024**2, 0, 1024**2)
    archive = RewardProofArchive(
        tmp_path / "bounded-export", physical_budget=ArchivePhysicalBudget(16 * 1024**2, 0, 1024**2)
    )
    h.target = RewardControlHistoryReader(
        h.target_root,
        **context,
        existing_only=True,
        physical_budget=budget,
        export_archive=archive,
        compact_export_only=True,
    )
    assert h.transfer()["transferred_blocks"] == h.end - h.source.first_block + 1
    for height in range(h.source.first_block, h.end + 1):
        await h.target._ensure_checkpoint_export(h.target.checkpoints.load(height))
    prohibit_proof_replay(monkeypatch, h.target)
    assert await h.target.advance(h.item.provider, through_block=h.end) == h.expected
    assert hashlib.sha256(h.source.journal.path.read_bytes()).hexdigest() == source_hash
    # Unchanged installed-style reader still consumes the ordinary checkpoint
    # format; no selected physical budget is needed to interpret successful facts.
    h.target = h.reopen_target()
    h.target.export_archive = archive
    prohibit_proof_replay(monkeypatch, h.target)
    assert await h.target.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.transfer()["transferred_blocks"] == 0
    assert hashlib.sha256(h.source.journal.path.read_bytes()).hexdigest() == source_hash


async def test_compact_only_refuses_fallback_without_expanding_proof(
    transfer_case, tmp_path, monkeypatch
):
    from umi import competition_reward_history as history

    h = transfer_case
    h.transfer()
    h.target.export_archive = RewardProofArchive(tmp_path / "compact-only")
    h.target.compact_export_only = True
    monkeypatch.setattr(history, "export_completed_checkpoint", lambda *a, **k: False)
    monkeypatch.setattr(h.target, "_load", lambda *a, **k: pytest.fail("legacy payload expansion"))
    checkpoint = h.target.checkpoints.load(h.source.first_block)
    with pytest.raises(ValueError, match="legacy fallback refused"):
        await h.target._ensure_checkpoint_export(checkpoint)
    assert h.target.checkpoints.load(h.source.first_block) == checkpoint
