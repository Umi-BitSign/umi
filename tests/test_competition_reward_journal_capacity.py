"""Configured standing capacity opens a tiny journal; no large allocation is needed."""

import bittensor as bt
import pytest

from umi.competition_reward_service import StandingRewardServiceLimits
from umi.competition_reward_transactions import MAX_STANDING_JOURNAL_BYTES, StandingWeightJournal
from umi.competition_round_journal import RoundJournal


def standing(root, maximum_bytes):
    return StandingWeightJournal(
        root,
        series_sha256="ab" * 32,
        validator_hotkey=bt.sp_core.ss58_encode(bytes.fromhex("11" * 32), 42),
        chain_config_sha256="cd" * 32,
        maximum_bytes=maximum_bytes,
    )


@pytest.mark.parametrize("maximum_bytes", [1024, 16 * 1024**3, 32 * 1024**3, 512 * 1024**3])
def test_service_capacity_is_accepted_by_actual_standing_constructor(tmp_path, maximum_bytes):
    limits = StandingRewardServiceLimits(maximum_journal_bytes=maximum_bytes, mortality_period=128)
    journal = standing(tmp_path / "weights", limits.maximum_journal_bytes)
    assert journal.journal.maximum_bytes == maximum_bytes
    assert journal.journal.MAXIMUM_BYTES == MAX_STANDING_JOURNAL_BYTES == 512 * 1024**3
    assert journal.pending() is None
    assert journal.journal.path.stat().st_size < 1024**2


@pytest.mark.parametrize("maximum_bytes", [1023, 512 * 1024**3 + 1, True, "34359738368"])
def test_parser_and_constructor_refuse_invalid_capacity_before_creating_state(
    tmp_path, maximum_bytes
):
    with pytest.raises(ValueError):
        StandingRewardServiceLimits(maximum_journal_bytes=maximum_bytes, mortality_period=128)
    root = tmp_path / "weights"
    with pytest.raises(ValueError, match="round journal requires bounded capacity"):
        standing(root, maximum_bytes)
    assert not root.exists()


def test_standing_capacity_upgrade_reopens_original_round_storage(tmp_path):
    root = tmp_path / "weights"
    binding = {
        "schema": "umi-standing-weight-journal/1",
        "series_sha256": "ab" * 32,
        "validator_account": "11" * 32,
        "chain_config_sha256": "cd" * 32,
    }
    old = RoundJournal(root, binding, maximum_bytes=16 * 1024**3)
    old.put("standing_host_identity", "original", "ef" * 32)
    old.put("retained_fixture", "signed", {"signed_bytes": "010203"})
    inode = old.path.stat().st_ino
    with old.read_transaction() as db:
        original = tuple(db.iterdump())
    for _ in range(2):
        reopened = standing(root, 32 * 1024**3)
        assert reopened.journal.path.stat().st_ino == inode
        assert reopened.journal.path.stat().st_size < 1024**2
        with reopened.journal.read_transaction() as db:
            assert tuple(db.iterdump()) == original
    # An existing owner and old supported reader keep their unchanged format.
    old.put("retained_fixture", "next", {"unchanged_format": True})
    assert reopened.journal.get("retained_fixture", "next") == {"unchanged_format": True}
    assert RoundJournal(root, binding, maximum_bytes=16 * 1024**3).get(
        "retained_fixture", "signed"
    ) == {"signed_bytes": "010203"}


def test_ordinary_round_journal_retains_16GiB_ceiling(tmp_path):
    assert RoundJournal.MAXIMUM_BYTES == 16 * 1024**3
    root = tmp_path / "rounds"
    with pytest.raises(ValueError, match="round journal requires bounded capacity"):
        RoundJournal(root, {}, maximum_bytes=16 * 1024**3 + 1)
    assert not root.exists()
