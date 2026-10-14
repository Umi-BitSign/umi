"""Logical journal admission survives real SQLite page and index overhead."""

import hashlib
import sqlite3
from contextlib import contextmanager

import pytest

from umi.competition_reward_history import _HistoryJournal
from umi.competition_round_journal import RoundJournal
from umi.protocol import canonical_json_bytes


def stored(journal):
    with journal.read_transaction() as db:
        return db.execute("SELECT number,nbytes FROM round_record_capacity").fetchone()


def legacy_full(journal, records, monkeypatch, *, batch_size=256):
    """Reproduce the previous connection-local ceiling with the native writer."""
    native_transaction = journal.transaction

    @contextmanager
    def old_transaction(**kwargs):
        with native_transaction(**kwargs) as db:
            db.execute(f"PRAGMA max_page_count={(journal.maximum_bytes + 16 * 1024**2) // 4096}")
            yield db

    with monkeypatch.context() as patch:
        patch.setattr(journal, "transaction", old_transaction)
        for first in range(0, len(records), batch_size):
            batch = records[first : first + batch_size]
            before = stored(journal)
            try:
                journal.put_many(batch)
            except sqlite3.OperationalError as error:
                assert error.sqlite_errorcode == sqlite3.SQLITE_FULL
                assert stored(journal) == before  # Entire failed batch rolls back.
                assert before[1] < journal.maximum_bytes
                return first
    pytest.fail("fixture did not reproduce the former physical ceiling")


def test_old_page_ceiling_failure_retries_same_native_batch(tmp_path, monkeypatch):
    budget = 24 * 1024**2
    binding = {"original": "native history owner"}
    journal = _HistoryJournal(tmp_path / "history", binding, maximum_bytes=budget)
    inode = journal.path.stat().st_ino
    records = []
    for number in range(budget // 2048):
        raw = number.to_bytes(8, "big") + b"x" * 1011
        value = {"hex": raw.hex()}
        assert len(canonical_json_bytes(value)) == 2048
        records.append(("control_history_object", hashlib.sha256(raw).hexdigest(), value))
    first = legacy_full(journal, records, monkeypatch)
    assert first > 0
    for low in range(first, len(records), 256):
        journal.put_many(records[low : low + 256])
    assert stored(journal) == (len(records), budget)
    assert journal.path.stat().st_size > budget + 16 * 1024**2
    with pytest.raises(ValueError, match="round journal capacity exhausted"):
        journal.put("control_history_object", "new", {})
    assert stored(journal) == (len(records), budget)
    for _ in range(2):
        journal = _HistoryJournal(journal.root, binding, maximum_bytes=budget)
        assert journal.path.stat().st_ino == inode
        for index in (0, first, len(records) - 1):
            kind, key, value = records[index]
            assert journal.get_raw(kind, key) == canonical_json_bytes(value)
            journal.put(kind, key, value)
        assert stored(journal) == (len(records), budget)


def test_small_records_with_large_indexes_keep_original_record_limit(tmp_path, monkeypatch):
    journal = RoundJournal(tmp_path / "rounds", {}, maximum_rounds=128, maximum_bytes=1024**2)
    records = [
        ("work", f"{number:08d}" + "k" * 1016, {}) for number in range(journal.maximum_records)
    ]
    first = legacy_full(journal, records, monkeypatch)
    for low in range(first, len(records), 256):
        journal.put_many(records[low : low + 256])
    assert stored(journal) == (journal.maximum_records, 2 * journal.maximum_records)
    assert journal.path.stat().st_size > journal.maximum_bytes + 16 * 1024**2
    with pytest.raises(ValueError, match="round journal capacity exhausted"):
        journal.put("work", "one too many", {})
    assert stored(journal) == (journal.maximum_records, 2 * journal.maximum_records)
    assert journal.get(*records[first][:2]) == {}


@pytest.mark.parametrize("journal_type", [RoundJournal, _HistoryJournal])
@pytest.mark.parametrize("page_size", [512, 1024, 8192, 65536])
def test_retained_page_size_and_exact_logical_allowance_survive_restart(
    tmp_path, journal_type, page_size
):
    root, binding = tmp_path / "journal", {"retained": True}
    journal = journal_type(root, binding, maximum_bytes=1024)
    inode = journal.path.stat().st_ino
    # Model an existing supported SQLite layout without changing logical rows.
    with sqlite3.connect(journal.path, isolation_level=None) as db:
        db.execute(f"PRAGMA page_size={page_size}")
        db.execute("VACUUM")
    for _ in range(2):
        journal = journal_type(root, binding, maximum_bytes=1024)
        journal.put("work", "full", "x" * 1022)
        with journal.read_transaction() as db:
            assert db.execute("PRAGMA page_size").fetchone()[0] == page_size
            assert db.execute("SELECT body FROM binding").fetchone()[0] == canonical_json_bytes(
                binding
            )
        assert journal.path.stat().st_ino == inode
        assert stored(journal) == (1, 1024)
        with pytest.raises(ValueError, match="round journal capacity exhausted"):
            journal.put_many([("work", "rejected", {}), ("work", "also rejected", {})])
        assert stored(journal) == (1, 1024)
        assert journal.get("work", "rejected") is None
