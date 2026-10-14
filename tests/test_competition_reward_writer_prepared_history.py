"""Native checkpoint directory selection semantics, without broker authority.

These tests preserve real journal inodes and use native history capabilities;
the finality/trie/codec ports are the explicit synthetic history fixture ports.
They qualify reuse at the original logical path, not root IPC or live cutover.
"""

import shutil

import pytest

from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired

from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_competition_reward_history_checkpoints import prohibit_proof_replay

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


async def test_prepared_directory_reuses_native_results_after_original_path_selection(
    history_case, tmp_path, monkeypatch
):
    h = history_case
    logical = h.reader.journal.root
    original_end = h.old.height + 1
    original = (await h.reader.advance(h.item.provider, through_block=original_end)).history
    original_owner = h.reader.checkpoints.owner
    original_inode = h.reader.journal.path.stat().st_ino
    saved_original, staged = tmp_path / "retained-original", tmp_path / "staged-candidate"
    logical.rename(saved_original)
    h.reader = h.new_reader()
    candidate = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    candidate_owner = h.reader.checkpoints.owner
    candidate_inode = h.reader.journal.path.stat().st_ino
    assert candidate_owner != original_owner and candidate_inode != original_inode
    original_prefix = await h.reader.verified_prefix(original_end)
    assert original_prefix == original
    logical.rename(staged)
    saved_original.rename(logical)

    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    restored_original = (
        await h.reader.advance(h.item.provider, through_block=original_end)
    ).history
    assert restored_original == original
    assert h.reader.checkpoints.owner == original_owner
    assert h.reader.journal.path.stat().st_ino == original_inode

    # The real broker must hold original/staged owners and make this durable.
    # Here the same-process native capabilities remain live across the fixture
    # switch; no serialized status document is accepted as prefix authority.
    logical.rename(saved_original)
    staged.rename(logical)
    h.reader = await h.restart()
    prohibit_proof_replay(monkeypatch, h.reader)
    h.body_requests.clear()
    restored_candidate = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    assert restored_candidate == candidate
    assert await h.reader.verified_prefix(original_end) == restored_original
    assert h.reader.checkpoints.owner == candidate_owner
    assert h.reader.journal.path.stat().st_ino == candidate_inode
    assert (saved_original / "rounds.sqlite3").stat().st_ino == original_inode
    assert not h.body_requests and h.reader.progress.native_completed == 0


@pytest.mark.parametrize("change", ["copied_directory", "different_logical_path"])
async def test_prepared_checkpoint_cannot_be_rebound_by_copy_or_alias(
    history_case, tmp_path, change
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    root = h.reader.journal.root
    other = tmp_path / "unapproved-history"
    if change == "copied_directory":
        shutil.copytree(root, other)
        root.rename(tmp_path / "preserved-original")
        other.rename(root)
    else:
        root.rename(other)
        root = other
    with pytest.raises(HistoryCheckpointRepairRequired, match="original owner changed"):
        RewardControlHistoryReader(
            root,
            control_hotkey=h.reader.hotkey,
            chain_config_sha256=h.reader.config_sha256,
            first_block=h.reader.first_block,
            maximum_bytes=h.reader.journal.maximum_bytes,
        )
